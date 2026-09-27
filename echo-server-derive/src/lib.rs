use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, LitStr, ReturnType, parse_macro_input};

// A procedural macro converting an async function into a
// struct of the same name that implements the `Route`
// trait in the `echo-server` crate.
#[proc_macro_attribute]
pub fn route(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(item as ItemFn);

    let mut needs_authentication = true;

    input.attrs.retain(|attr| {
        let maybe_ident = attr
            .path()
            .segments
            .first()
            .map(|seg| &seg.ident);

        let Some(ident) = maybe_ident else {
            return true;
        };

        if ident == "no_auth" {
            needs_authentication = false;

            return false;
        }

        true
    });

    let fn_name = &input.sig.ident;
    let route_name = parse_macro_input!(attr as LitStr);

    let callback = &*input.block;

    let ret_type = match &input.sig.output {
        ReturnType::Default => &syn::parse_str("()").expect("failed to parse default value"),
        ReturnType::Type(_, ty) => &**ty
    };

    quote! {
        #[allow(non_camel_case_types)]
        pub struct #fn_name;

        #[::async_trait::async_trait]
        impl crate::router::EchoRoute for #fn_name {
            fn name(&self) -> &'static str {
                #route_name
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

                let _ = ctx.stream.send(&stripped).await;

                result.map(|_| ())
            }
        }
    }.into()
}
