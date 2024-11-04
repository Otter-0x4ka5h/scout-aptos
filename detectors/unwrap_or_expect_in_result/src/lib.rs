#![feature(rustc_private)]
#![feature(never_type)]
#![warn(unused_extern_crates)]


extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_then;
use clippy_utils::ty::is_type_diagnostic_item;
use clippy_utils::visitors::for_each_expr;
use clippy_utils::{method_chain_args, return_ty};
use core::ops::ControlFlow;
use rustc_hir as hir;
use rustc_hir::{ImplItemKind, FnDecl};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{Span, sym};
use rustc_span::def_id::LocalDefId;


const LINT_MESSAGE: &str = "Avoid using `unwrap` or `expect` in functions that return `Result` or `Option`.";
const LINT_HELP: &str = "Use proper error handling instead of `unwrap` or `expect` to avoid panics in functions returning `Result` or `Option`.";

scout_audit_dylint_linting::declare_late_lint! {
    pub UNWRAP_OR_EXPECT_IN_RESULT,
    Warn,
    LINT_MESSAGE,
    {
        name: "Unwrap or Expect Inside Result",
        long_message: LINT_MESSAGE,
        severity: "Medium",
        help: "Consider using proper error handling instead of `unwrap` or `expect`.",
        vulnerability_class: "Error Handling",
    }
}

impl<'tcx> LateLintPass<'tcx> for UnwrapOrExpectInResult {
    fn check_impl_item(&mut self, cx: &LateContext<'tcx>, impl_item: &'tcx hir::ImplItem<'_>) {
        if let ImplItemKind::Fn(_, body_id) = impl_item.kind {
            let body = cx.tcx.hir().body(body_id);
            if is_type_diagnostic_item(cx, return_ty(cx, impl_item.owner_id), sym::Result)
            {
                lint_impl_body(cx, body, impl_item.span, impl_item.owner_id.def_id);
            }
        }
    }

    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        _fn_kind: hir::intravisit::FnKind<'tcx>,
        _fn_decl: &'tcx FnDecl<'tcx>,
        body_id: &'tcx rustc_hir::Body<'tcx>,
        fn_span: Span,
        hir_id: LocalDefId,
    ) {
        let body = cx.tcx.hir().body(body_id.id());
        if is_type_diagnostic_item(cx, return_ty(cx, rustc_hir::OwnerId { def_id: hir_id }), sym::Result)
        {
            lint_impl_body(cx, body, fn_span, hir_id);
        }
    }
}

fn lint_impl_body<'tcx>(cx: &LateContext<'tcx>,  body: &'tcx hir::Body<'_>, impl_span: Span, owner_id: LocalDefId) {
    let mut result = Vec::new();
    let typeck = cx.tcx.typeck(owner_id); // Get typeck with LocalDefId

    let _: Option<!> = for_each_expr(body.value, |e| {
        if let Some(arglists) = method_chain_args(e, &["unwrap"]) {
            let receiver_ty = typeck.expr_ty(arglists[0].0).peel_refs();
            if is_type_diagnostic_item(cx, receiver_ty, sym::Option) || is_type_diagnostic_item(cx, receiver_ty, sym::Result) {
                result.push(e.span);
            }
        }

        if let Some(arglists) = method_chain_args(e, &["expect"]) {
            let receiver_ty = typeck.expr_ty(arglists[0].0).peel_refs();
            if is_type_diagnostic_item(cx, receiver_ty, sym::Option) || is_type_diagnostic_item(cx, receiver_ty, sym::Result) {
                result.push(e.span);
            }
        }

        ControlFlow::Continue(())
    });

    if !result.is_empty() {
        span_lint_and_then(
            cx,
            UNWRAP_OR_EXPECT_IN_RESULT,
            impl_span,
            "using `unwrap` or `expect` inside a function that returns `Result` or `Option`",
            |diag| {
                diag.help("consider handling the error instead of using `unwrap` or `expect`.");
                diag.span_note(result, "found `unwrap` or `expect` here");
            },
        );
    }
}