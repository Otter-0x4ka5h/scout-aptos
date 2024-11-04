#![feature(rustc_private)]
#![feature(never_type)]
#![warn(unused_extern_crates)]


extern crate rustc_hir;
extern crate rustc_span;

use rustc_lint::{LateContext, LateLintPass};
use clippy_utils::return_ty;
use clippy_utils::diagnostics::span_lint_and_then;
use clippy_utils::ty::is_type_diagnostic_item;
use clippy_utils::visitors::for_each_expr;
use core::ops::ControlFlow;
use rustc_hir as hir;
use rustc_hir::{ImplItemKind, FnDecl};
use rustc_span::{Span, sym};
use rustc_span::def_id::LocalDefId;

const LINT_MESSAGE: &str = "Used unsafe indexing in a function that returns Result";
const LINT_HELP: &str = "Avoid using direct indexing in functions that return `Result`. Use `.get()` or handle the error case explicitly.";

scout_audit_dylint_linting::declare_late_lint! {
    pub INDEX_IN_RESULT,
    Warn,
    LINT_MESSAGE,
    {
        name: "Index In Result",
        long_message: LINT_MESSAGE,
        severity: "High",
        help: "Consider using safer alternatives like `.get()` to avoid panicking on out-of-bounds indexing.",
        vulnerability_class: "Memory Safety",
    }
}

impl<'tcx> LateLintPass<'tcx> for IndexInResult {
    // Called for methods inside `impl` blocks
    fn check_impl_item(&mut self, cx: &LateContext<'tcx>, impl_item: &'tcx hir::ImplItem<'_>) {
        if let ImplItemKind::Fn(_, body_id) = impl_item.kind {
            check_fun_body(cx, cx.tcx.hir().body(body_id), impl_item.span, impl_item.owner_id.def_id);
        }
    }

    // Called for top-level functions
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
        check_fun_body(cx, body, fn_span, hir_id);
    }
}

// This function checks both top-level functions and methods inside impl blocks
fn check_fun_body<'tcx>(cx: &LateContext<'tcx>, body: &'tcx hir::Body<'_>, span: Span, hir_id: LocalDefId) {
    if is_type_diagnostic_item(cx, return_ty(cx, rustc_hir::OwnerId { def_id: hir_id }), sym::Result) {
        lint_body(cx, span, body);
    }
}

fn lint_body<'tcx>(cx: &LateContext<'tcx>, span: Span, body: &'tcx hir::Body<'_>) {
    let mut unsafe_indexes = Vec::new();

    let _: Option<!> = for_each_expr(body.value, |e| {
        if let hir::ExprKind::Index(..) = e.kind {
            unsafe_indexes.push(e.span);
        }
        ControlFlow::Continue(())
    });

    if !unsafe_indexes.is_empty() {
        span_lint_and_then(
            cx,
            INDEX_IN_RESULT,
            span,
            "unsafe indexing in a function that returns `Result`",
            |diag| {
                diag.help("consider using `.get()` or proper error handling for safe access");
                diag.span_note(unsafe_indexes, "unsafe indexing detected");
            },
        );
    }
}