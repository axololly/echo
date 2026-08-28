use proc_macro::TokenStream;
use quote::{ToTokens, quote};
use syn::{Expr, ItemFn, Lit, LitStr, ReturnType, Token, parse::{Parse, ParseStream}, parse_macro_input, punctuated::Punctuated};

struct RateLimitAttr {
    num_times: usize,
    per_secs: u64
}

impl Parse for RateLimitAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let vars = Punctuated::<Expr, Token![,]>::parse_terminated(input)?;
        let mut iter = vars.iter();

        let num_times = iter
            .next()
            .iter()
            .filter_map(|expr| match expr {
                Expr::Lit(lit) => Some(&lit.lit),
                _ => None
            })
            .filter_map(|lit| match lit {
                Lit::Int(i) => Some(i),
                _ => None
            })
            .filter_map(|i| i.base10_parse::<usize>().ok())
            .next()
            .ok_or(syn::Error::new_spanned(
                input.cursor().token_stream(),
                "Expected a valid u64 as first argument"
            ))?;

        let window_duration = iter
            .next()
            .map(|expr| expr.to_token_stream().to_string())
            .ok_or(syn::Error::new_spanned(
                input.cursor().token_stream(),
                "Expected duration as second argument"
            ))?;

        let per_secs = parse_duration(&window_duration);

        Ok(Self {
            num_times,
            per_secs
        })
    }
}

fn parse_duration(raw: &str) -> u64 {
    let mut seconds = 0;

    let calc = |unit| match unit {
        "d" => 24 * 60 * 60,
        "h" => 60 * 60,
        "m" => 60,
        "s" => 1,
        _ => panic!("invalid unit: {unit:?}")
    };

    for part in raw.split_whitespace() {
        let (rest, ending) = part.split_at(part.len() - 1);

        let amount: u64 = rest.parse().expect("invalid u64 found when parsing duration");

        seconds += amount * calc(ending);
    }

    seconds
}

#[proc_macro_attribute]
pub fn route(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(item as ItemFn);

    let mut needs_authentication = true;
    let mut rate_limit: Option<RateLimitAttr> = None;

    input.attrs.retain(|attr| {
        let maybe_ident = attr
            .path()
            .segments
            .first()
            .map(|seg| &seg.ident);

        let Some(ident) = maybe_ident else {
            return true;
        };

        if ident == "ratelimit" {
            if rate_limit.is_some() {
                panic!("duplicate ratelimit attributes");
            }

            let list = attr
                .meta
                .require_list()
                .expect("did not get list of metadata");

            let rate_limit_attr: RateLimitAttr = syn::parse2(list.tokens.clone())
                .expect("failed to parse rate limit attr");

            rate_limit = Some(rate_limit_attr);

            return false;
        }

        if ident == "no_auth" {
            needs_authentication = false;

            return false;
        }

        true
    });

    let fn_name = &input.sig.ident;
    let resource = parse_macro_input!(attr as LitStr);

    let rate_limit = match rate_limit {
        Some(limit) => {
            let RateLimitAttr { num_times, per_secs } = limit;

            quote! {
                Some(crate::router::RateLimit {
                    num_times: #num_times,
                    per_secs: #per_secs
                })
            }
        },
        None => quote! { None }
    };

    let callback = &*input.block;

    let ret_type = match &input.sig.output {
        ReturnType::Default => &syn::parse_str("()").expect("failed to parse default value"),
        ReturnType::Type(_, ty) => &**ty
    };

    quote! {
        #[allow(non_camel_case_types)]
        pub struct #fn_name;

        impl #fn_name {
            pub async fn call(&self, ctx: &mut EchoContext) -> #ret_type {
                #callback
            }
        }

        #[::async_trait::async_trait]
        impl crate::router::Route<EchoContext> for #fn_name {
            fn resource(&self) -> &'static str {
                #resource
            }

            fn rate_limit(&self) -> Option<crate::router::RateLimit> {
                #rate_limit
            }

            fn needs_authentication(&self) -> bool {
                #needs_authentication
            }

            async fn callback(&self, ctx: &mut EchoContext) -> crate::error::RouteResult<()> {
                let result: #ret_type = #callback;

                let stripped = match &result {
                    Ok(v) => Ok(v),
                    Err(report) => Err(report.current_context())
                };

                let _ = ctx.conn.send(&stripped).await;

                result.map(|_| ())
            }
        }
    }.into()
}
