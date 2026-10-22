use std::{collections::HashMap, time::Duration};

use proc_macro::TokenStream;
use quote::quote;
use syn::{Expr, ExprLit, Ident, ItemFn, Lit, MetaNameValue, ReturnType, Token, parse_macro_input, parse2, punctuated::Punctuated};

#[proc_macro_attribute]
pub fn interval(
    args: TokenStream,
    item: TokenStream
) -> TokenStream {
    let interval_args = parse_macro_input!(
        args with Punctuated<MetaNameValue, Token![,]>::parse_terminated
    );

    let mut duration = Duration::ZERO;

    let mut valid_units: HashMap<&str, &dyn Fn(u64) -> Duration> = HashMap::new();

    valid_units.insert("weeks", &|v| Duration::from_hours(v * 24 * 7));
    valid_units.insert("days", &|v| Duration::from_hours(v * 24));
    valid_units.insert("hours", &Duration::from_hours);
    valid_units.insert("mins", &|v| Duration::from_secs(v * 60));
    valid_units.insert("secs", &Duration::from_secs);

    for nv in interval_args {
        let Expr::Lit(ExprLit { lit: Lit::Int(int), .. }) = nv.value else {
            panic!("expected a literal integer for interval args");
        };

        let value = int.base10_parse::<u64>().expect("cannot parse {int} as a u64");

        let ident_owned = nv
            .path
            .get_ident()
            .map(|i| i.to_string());

        let ident = ident_owned
            .as_deref()
            .unwrap_or("<no ident>");

        let make_duration = valid_units
            .remove(ident)
            .unwrap_or_else(|| panic!("duplicate values for parameter: {ident}"));

        duration += make_duration(value);
    }

    let mut callback = parse_macro_input!(item as ItemFn);

    let fn_name = &callback.sig.ident;
    let ret_type = &callback.sig.output;

    if matches!(ret_type, ReturnType::Default) {
        panic!("return type must be explicitly labelled");
    }

    let body = &callback.block;

    let mut on_error = None;
    let mut before_start = None;
    let mut after_finish = None;

    callback.attrs.retain(|attr| {
        let is_attr_name = |name| attr.meta.path().is_ident(name);

        let grab_single_ident = || -> Option<Ident> {
            let Ok(list) = attr.meta.require_list() else {
                return None;
            };

            parse2(list.tokens.clone()).ok()
        };

        if is_attr_name("on_error") {
            let Some(error_handler) = grab_single_ident() else {
                return true;
            };

            if on_error.is_some() {
                panic!("function {fn_name:?} has multiple error handlers (only allowed one)");
            }

            on_error = Some(quote! {
                #[allow(unused)]
                if let Err(e) = _result {
                    #error_handler(e).await;
                }
            });
        }

        if is_attr_name("before_start") {
            let Some(before_start_handler) = grab_single_ident() else {
                return true;
            };

            if before_start.is_some() {
                panic!("function {fn_name:?} has multiple before-start handlers (only allowed one)");
            }

            before_start = Some(quote! {
                #before_start_handler().await?;
            });
        }

        if is_attr_name("after_finish") {
            let Some(after_finish_handler) = grab_single_ident() else {
                return true;
            };

            if after_finish.is_some() {
                panic!("function {fn_name:?} has multiple after-finish handlers (only allowed one)");
            }

            after_finish = Some(quote! {
                #after_finish_handler().await?;
            });
        }

        false
    });

    let before_start = before_start.unwrap_or(quote! {});
    let after_finish = after_finish.unwrap_or(quote! {});

    let on_error = on_error.unwrap_or(quote! {});

    let secs = duration.as_secs();
    let nanos = duration.subsec_nanos();

    let task_name = Ident::new(
        &format!("__{fn_name}_task_impl"),
        fn_name.span()
    );

    let wrapper_name = Ident::new(
        &format!("__{fn_name}_wrapper_impl"),
        fn_name.span()
    );

    quote! {
        #[allow(non_camel_case_types)]
        struct #task_name;

        #[::async_trait::async_trait]
        impl ::backoffice::task::Task for #task_name {
            fn interval(&self) -> ::std::time::Duration {
                ::std::time::Duration::new(#secs, #nanos)
            }

            async fn callback(&self) {
                let inner = async || #ret_type {
                    #body
                };

                let wrapped = async || #ret_type {
                    #before_start
                    inner().await?;
                    #after_finish
                    Ok(())
                };

                let _result = wrapped().await;

                #on_error
            }
        }

        #[allow(non_camel_case_types)]
        struct #wrapper_name {
            internal: ::std::sync::LazyLock<::backoffice::task::RunningTask>
        }

        impl #wrapper_name {
            /// Create a new task. Running has to be done explicitly.
            pub const fn new() -> Self {
                Self {
                    internal: ::std::sync::LazyLock::new(|| {
                        ::backoffice::task::RunningTask::new(#task_name)
                    })
                }
            }

            /// Start running the task.
            pub fn start(&self) {
                self.internal.start();
            }

            /// Stop running the task.
            ///
            /// This allows the task to finish its current cycle
            /// before stopping the loop.
            pub fn stop(&self) {
                self.internal.stop();
            }

            /// Cancel the internal task.
            pub fn cancel(&self) {
                self.internal.cancel();
            }
        }

        #[allow(non_upper_case_globals)]
        pub static #fn_name: #wrapper_name = #wrapper_name::new();
    }.into()
}
