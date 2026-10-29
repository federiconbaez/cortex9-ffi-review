//! ffi-review: lists FFI boundaries and unsafe operations of a Rust crate with
//! a risk ranking, a review checklist per finding and generated tests for
//! miri / AddressSanitizer.
//!
//! The analysis is purely syntactic (syn): no type information, no macro
//! expansion. See README for what that means in practice.

use proc_macro2::Span;
use quote::ToTokens;
use serde::Serialize;
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low = 1,
    Medium = 2,
    High = 3,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    /// `Type::method`, `function`, or `<module>` when outside any fn.
    pub function: String,
    pub kind: &'static str,
    pub risk: Risk,
    pub detail: String,
    pub checklist: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Param {
    pub name: String,
    pub ty: String,
}

/// A Rust function exported to C (`#[no_mangle]` + non-Rust ABI).
#[derive(Debug, Clone, Serialize)]
pub struct Export {
    pub symbol: String,
    pub abi: String,
    pub params: Vec<Param>,
    pub ret: Option<String>,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub root: String,
    pub files_scanned: usize,
    pub parse_errors: Vec<String>,
    pub findings: Vec<Finding>,
    pub exports: Vec<Export>,
    /// Library crate name from Cargo.toml (`-` replaced by `_`), if found.
    pub crate_name: Option<String>,
    /// `.rs` files present but not reached from the crate's module tree
    /// (build scripts, test fixtures, tests/ when skipped...). Not analysed.
    pub not_in_module_tree: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FnScore {
    pub function: String,
    pub file: String,
    pub score: u32,
    pub findings: usize,
    pub max_risk: Risk,
}

impl Report {
    /// Functions ranked by summed risk weight (desc), ties by name.
    pub fn ranking(&self) -> Vec<FnScore> {
        let mut map: std::collections::BTreeMap<(String, String), FnScore> = Default::default();
        for f in &self.findings {
            let e = map
                .entry((f.file.clone(), f.function.clone()))
                .or_insert(FnScore {
                    function: f.function.clone(),
                    file: f.file.clone(),
                    score: 0,
                    findings: 0,
                    max_risk: Risk::Low,
                });
            e.score += f.risk as u32;
            e.findings += 1;
            e.max_risk = e.max_risk.max(f.risk);
        }
        let mut v: Vec<FnScore> = map.into_values().collect();
        v.sort_by(|a, b| b.score.cmp(&a.score).then(a.function.cmp(&b.function)));
        v
    }
}

const CK_IMPORT: &str = "Who owns returned pointers? Can the C side return NULL? Are lengths in bytes or elements? Is the callee thread-safe?";
const CK_EXPORT: &str = "Validate every pointer (NULL, alignment, length) before use; never let a panic unwind into C; document who frees what.";
const CK_PANIC: &str = "Wrap the body in std::panic::catch_unwind (or use extern \"C-unwind\") and map panics to an error code.";
const CK_NULL: &str = "Check each raw pointer parameter for NULL (and length 0) before dereferencing or building a slice from it.";
const CK_SLICE: &str = "Pointer non-null and aligned, len in elements (not bytes), memory initialized and alive for the whole lifetime of the slice, no aliasing &mut.";
const CK_OWN: &str = "The pointer must come from the matching into_raw/allocator of the same type, exactly once (double free / wrong allocator otherwise).";
const CK_TRANSMUTE: &str = "Same size and alignment, every bit pattern valid for the target type, lifetimes not extended.";
const CK_SETLEN: &str = "All elements up to new_len initialized before set_len; new_len <= capacity; no panic between set_len and initialization.";
const CK_UNCHECKED: &str = "Prove the index/invariant is in bounds on every path, including after earlier mutations.";
const CK_PTR: &str = "Source/destination valid for the access size, aligned (or *_unaligned used), non-overlapping where required, offsets stay inside one allocation.";
const CK_CSTR: &str = "Pointer non-null, NUL-terminated within the allocation, alive for the borrowed lifetime.";
const CK_UNINIT: &str = "Value fully initialized before assume_init / never read uninitialized; mem::uninitialized is UB for most types.";
const CK_SENDSYNC: &str = "Prove the type is safe to send/share across threads for every generic parameter (add T: Send/Sync bounds?).";
const CK_UNSAFE_IMPL: &str = "Check the trait's documented safety contract holds for every instance.";
const CK_UNSAFE_FN: &str = "Document # Safety preconditions; check every caller upholds them.";
const CK_STATIC_MUT: &str = "Any concurrent access is a data race; prefer atomics/OnceLock/Mutex.";
const CK_CAST: &str = "Pointer provenance and type: does the pointee really have this type and layout (#[repr(C)])?";
const CK_CONST_MUT: &str = "Writing through a pointer derived from a shared reference/as_ptr is UB.";
const CK_DANGLING: &str = "The CString is dropped at the end of the statement; the pointer dangles. Bind it to a variable that outlives the call.";
const CK_TO_RAW: &str = "Who frees this? Leak or double free if the C side does not return it exactly once.";
const CK_UTF8: &str = "Bytes must be valid UTF-8 on every path.";
const CK_UNSAFE_BLOCK: &str = "Write down the invariant (// SAFETY:) that makes this block sound and check every caller-controlled input.";

pub struct Scanner<'a> {
    file: &'a str,
    pub findings: Vec<Finding>,
    pub exports: Vec<Export>,
    fn_stack: Vec<String>,
    self_ty: Vec<String>,
    unsafe_depth: usize,
    /// also analyse #[cfg(test)] modules and #[test] fns
    pub include_tests: bool,
}

fn line_of(span: Span) -> usize {
    span.start().line
}

fn compact(ts: &impl ToTokens) -> String {
    let s = ts.to_token_stream().to_string();
    let s = s.replace(" :: ", "::").replace(" < ", "<").replace(" >", ">").replace("* const", "*const").replace("* mut", "*mut");
    if s.len() > 120 {
        format!("{}…", &s[..s.char_indices().nth(117).map(|(i, _)| i).unwrap_or(s.len())])
    } else {
        s
    }
}

fn last_ident(path: &syn::Path) -> String {
    path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default()
}

fn path_str(path: &syn::Path) -> String {
    path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::")
}

fn type_name(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(p) => last_ident(&p.path),
        syn::Type::Reference(r) => type_name(&r.elem),
        syn::Type::Group(g) => type_name(&g.elem),
        syn::Type::Paren(p) => type_name(&p.elem),
        other => compact(other),
    }
}

fn is_raw_ptr(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Ptr(_))
}

fn has_attr(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|a| {
        let p = a.path();
        if p.is_ident(name) {
            return true;
        }
        // #[unsafe(no_mangle)] (edition 2024)
        if p.is_ident("unsafe") {
            return a.to_token_stream().to_string().contains(name);
        }
        false
    })
}

fn abi_name(abi: &Option<syn::Abi>) -> Option<String> {
    let abi = abi.as_ref()?;
    let name = abi.name.as_ref().map(|n| n.value()).unwrap_or_else(|| "C".to_string());
    if name == "Rust" {
        None
    } else {
        Some(name)
    }
}

/// Collects facts about a fn body that the export checks need.
#[derive(Default)]
struct BodyFacts {
    idents: std::collections::HashSet<String>,
    panicky: bool,
    catch_unwind: bool,
}

impl<'ast> Visit<'ast> for BodyFacts {
    fn visit_ident(&mut self, i: &'ast proc_macro2::Ident) {
        self.idents.insert(i.to_string());
    }
    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        let n = m.method.to_string();
        if n == "unwrap" || n == "expect" {
            self.panicky = true;
        }
        if n == "is_null" {
            self.idents.insert("is_null".into());
        }
        visit::visit_expr_method_call(self, m);
    }
    fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
        if last_ident(&p.path) == "catch_unwind" {
            self.catch_unwind = true;
        }
        visit::visit_expr_path(self, p);
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        let n = last_ident(&m.path);
        if matches!(n.as_str(), "panic" | "unreachable" | "todo" | "unimplemented" | "assert" | "assert_eq" | "assert_ne") {
            self.panicky = true;
        }
        // identifiers inside macro bodies (e.g. assert!(!p.is_null()))
        for tt in m.tokens.clone() {
            collect_idents(tt, &mut self.idents);
        }
    }
    fn visit_expr_index(&mut self, i: &'ast syn::ExprIndex) {
        self.panicky = true;
        visit::visit_expr_index(self, i);
    }
}

fn collect_idents(tt: proc_macro2::TokenTree, out: &mut std::collections::HashSet<String>) {
    match tt {
        proc_macro2::TokenTree::Ident(i) => {
            out.insert(i.to_string());
        }
        proc_macro2::TokenTree::Group(g) => {
            for t in g.stream() {
                collect_idents(t, out);
            }
        }
        _ => {}
    }
}

impl<'a> Scanner<'a> {
    pub fn new(file: &'a str) -> Self {
        Scanner { file, findings: vec![], exports: vec![], fn_stack: vec![], self_ty: vec![], unsafe_depth: 0, include_tests: false }
    }

    fn current_fn(&self) -> String {
        match self.fn_stack.last() {
            Some(f) => f.clone(),
            None => "<module>".into(),
        }
    }

    fn push(&mut self, span: Span, kind: &'static str, risk: Risk, detail: String, checklist: &'static str) {
        self.findings.push(Finding {
            file: self.file.to_string(),
            line: line_of(span),
            function: self.current_fn(),
            kind,
            risk,
            detail,
            checklist,
        });
    }

    fn qualified(&self, name: &str) -> String {
        match self.self_ty.last() {
            Some(t) => format!("{t}::{name}"),
            None => name.to_string(),
        }
    }

    fn check_fn(&mut self, attrs: &[syn::Attribute], sig: &syn::Signature, block: Option<&syn::Block>) {
        let name = sig.ident.to_string();
        let span = sig.ident.span();
        if sig.unsafety.is_some() {
            self.push(span, "unsafe-fn", Risk::Low, format!("unsafe fn {name}"), CK_UNSAFE_FN);
        }
        let Some(abi) = abi_name(&sig.abi) else { return };
        let no_mangle = has_attr(attrs, "no_mangle") || has_attr(attrs, "export_name");
        self.push(span, "extern-export", Risk::Medium, format!("extern \"{abi}\" fn {name}{}", if no_mangle { " (#[no_mangle])" } else { "" }), CK_EXPORT);
        let mut ptr_params = vec![];
        let mut params = vec![];
        for input in &sig.inputs {
            if let syn::FnArg::Typed(pt) = input {
                let pname = match &*pt.pat {
                    syn::Pat::Ident(i) => i.ident.to_string(),
                    other => compact(other),
                };
                if is_raw_ptr(&pt.ty) {
                    ptr_params.push(pname.clone());
                }
                params.push(Param { name: pname, ty: compact(&*pt.ty) });
            }
        }
        if let Some(block) = block {
            let mut facts = BodyFacts::default();
            facts.visit_block(block);
            if !abi.ends_with("-unwind") && !facts.catch_unwind {
                let risk = if facts.panicky { Risk::High } else { Risk::Medium };
                self.push(span, "panic-across-ffi", risk, format!("no catch_unwind in extern \"{abi}\" fn {name}{}", if facts.panicky { "; body has unwrap/expect/panic!/indexing" } else { "" }), CK_PANIC);
            }
            for p in &ptr_params {
                // the parameter must be used and never compared with null
                if facts.idents.contains(p) && !facts.idents.contains("is_null") && !facts.idents.contains("NonNull") {
                    self.push(span, "no-null-check", Risk::High, format!("raw pointer parameter `{p}` of {name} used without an is_null() check"), CK_NULL);
                }
            }
        }
        if no_mangle {
            let symbol = export_symbol(attrs).unwrap_or(name);
            let ret = match &sig.output {
                syn::ReturnType::Default => None,
                syn::ReturnType::Type(_, t) => Some(compact(&**t)),
            };
            self.exports.push(Export { symbol, abi, params, ret, file: self.file.to_string(), line: line_of(span) });
        }
    }

    fn check_call_path(&mut self, path: &syn::Path, span: Span) {
        let last = last_ident(path);
        let full = path_str(path);
        let in_unsafe = self.unsafe_depth > 0;
        let (kind, risk, ck): (&'static str, Risk, &'static str) = match last.as_str() {
            "from_raw_parts" | "from_raw_parts_mut" if full.starts_with("Vec") || full.starts_with("String") => ("ownership-from-raw", Risk::High, CK_OWN),
            "from_raw_parts" | "from_raw_parts_mut" => ("raw-slice", Risk::High, CK_SLICE),
            "from_raw" => ("ownership-from-raw", Risk::High, CK_OWN),
            "transmute" | "transmute_copy" => ("transmute", Risk::High, CK_TRANSMUTE),
            "uninitialized" => ("uninit", Risk::High, CK_UNINIT),
            "zeroed" => ("uninit", Risk::Medium, CK_UNINIT),
            "from_ptr" => ("cstr-from-ptr", Risk::Medium, CK_CSTR),
            "from_utf8_unchecked" | "from_utf8_unchecked_mut" => ("utf8-unchecked", Risk::Medium, CK_UTF8),
            "read" | "write" | "copy" | "copy_nonoverlapping" | "read_unaligned" | "write_unaligned" | "read_volatile" | "write_volatile" | "swap" | "replace" | "drop_in_place" | "write_bytes"
                if full.contains("ptr::") || full.starts_with("ptr") || full.starts_with("intrinsics") =>
            {
                ("ptr-read-write", Risk::Medium, CK_PTR)
            }
            "forget" | "into_raw" | "leak" if !in_unsafe => ("ownership-to-raw", Risk::Low, CK_TO_RAW),
            "forget" | "into_raw" | "leak" => ("ownership-to-raw", Risk::Low, CK_TO_RAW),
            _ => return,
        };
        // calls that are only dangerous inside unsafe: report them there; safe
        // ownership transfers are reported anywhere.
        if !in_unsafe && kind != "ownership-to-raw" {
            return;
        }
        self.push(span, kind, risk, format!("{full}(..)"), ck);
    }
}

fn export_symbol(attrs: &[syn::Attribute]) -> Option<String> {
    for a in attrs {
        if a.path().is_ident("export_name") {
            if let syn::Meta::NameValue(nv) = &a.meta {
                if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) = &nv.value {
                    return Some(s.value());
                }
            }
        }
    }
    None
}

fn is_test_code(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        if a.path().is_ident("test") {
            return true;
        }
        if a.path().is_ident("cfg") {
            let t = a.to_token_stream().to_string().replace(' ', "");
            return t == "#[cfg(test)]";
        }
        false
    })
}

impl<'ast, 'a> Visit<'ast> for Scanner<'a> {
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if !self.include_tests && is_test_code(&m.attrs) {
            return;
        }
        visit::visit_item_mod(self, m);
    }

    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if !self.include_tests && is_test_code(&f.attrs) {
            return;
        }
        let name = f.sig.ident.to_string();
        self.fn_stack.push(name);
        // a nested fn is not a method of the surrounding impl
        let saved = std::mem::take(&mut self.self_ty);
        self.check_fn(&f.attrs, &f.sig, Some(&f.block));
        if f.sig.unsafety.is_some() {
            self.unsafe_depth += 1;
            visit::visit_item_fn(self, f);
            self.unsafe_depth -= 1;
        } else {
            visit::visit_item_fn(self, f);
        }
        self.self_ty = saved;
        self.fn_stack.pop();
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        let q = self.qualified(&f.sig.ident.to_string());
        self.fn_stack.push(q);
        self.check_fn(&f.attrs, &f.sig, Some(&f.block));
        if f.sig.unsafety.is_some() {
            self.unsafe_depth += 1;
            visit::visit_impl_item_fn(self, f);
            self.unsafe_depth -= 1;
        } else {
            visit::visit_impl_item_fn(self, f);
        }
        self.fn_stack.pop();
    }

    fn visit_trait_item_fn(&mut self, f: &'ast syn::TraitItemFn) {
        let q = self.qualified(&f.sig.ident.to_string());
        self.fn_stack.push(q);
        self.check_fn(&f.attrs, &f.sig, f.default.as_ref());
        if f.sig.unsafety.is_some() {
            self.unsafe_depth += 1;
            visit::visit_trait_item_fn(self, f);
            self.unsafe_depth -= 1;
        } else {
            visit::visit_trait_item_fn(self, f);
        }
        self.fn_stack.pop();
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let ty = type_name(&i.self_ty);
        if i.unsafety.is_some() {
            let trait_name = i.trait_.as_ref().map(|(_, p, _)| last_ident(p)).unwrap_or_default();
            let (kind, risk, ck) = if trait_name == "Send" || trait_name == "Sync" {
                ("unsafe-send-sync", Risk::High, CK_SENDSYNC)
            } else {
                ("unsafe-impl", Risk::Medium, CK_UNSAFE_IMPL)
            };
            self.fn_stack.push(format!("{ty}::<impl {trait_name}>"));
            self.push(i.impl_token.span, kind, risk, format!("unsafe impl {trait_name} for {}", compact(&*i.self_ty)), ck);
            self.fn_stack.pop();
        }
        self.self_ty.push(ty);
        visit::visit_item_impl(self, i);
        self.self_ty.pop();
    }

    fn visit_item_trait(&mut self, t: &'ast syn::ItemTrait) {
        self.self_ty.push(t.ident.to_string());
        visit::visit_item_trait(self, t);
        self.self_ty.pop();
    }

    fn visit_item_foreign_mod(&mut self, m: &'ast syn::ItemForeignMod) {
        let abi = m.abi.name.as_ref().map(|n| n.value()).unwrap_or_else(|| "C".into());
        for item in &m.items {
            if let syn::ForeignItem::Fn(f) = item {
                let saved = std::mem::take(&mut self.fn_stack);
                self.fn_stack.push(f.sig.ident.to_string());
                self.push(f.sig.ident.span(), "extern-import", Risk::Low, format!("extern \"{abi}\" {{ fn {} }}", compact(&f.sig)), CK_IMPORT);
                self.fn_stack = saved;
            }
        }
        visit::visit_item_foreign_mod(self, m);
    }

    fn visit_item_static(&mut self, s: &'ast syn::ItemStatic) {
        if matches!(s.mutability, syn::StaticMutability::Mut(_)) {
            self.push(s.ident.span(), "static-mut", Risk::Medium, format!("static mut {}", s.ident), CK_STATIC_MUT);
        }
        visit::visit_item_static(self, s);
    }

    fn visit_expr_unsafe(&mut self, u: &'ast syn::ExprUnsafe) {
        self.push(u.unsafe_token.span, "unsafe-block", Risk::Low, "unsafe { .. }".into(), CK_UNSAFE_BLOCK);
        self.unsafe_depth += 1;
        visit::visit_expr_unsafe(self, u);
        self.unsafe_depth -= 1;
    }

    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*c.func {
            let span = p.path.segments.last().map(|s| s.ident.span()).unwrap_or_else(Span::call_site);
            self.check_call_path(&p.path, span);
        }
        visit::visit_expr_call(self, c);
    }

    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        let n = m.method.to_string();
        let span = m.method.span();
        let in_unsafe = self.unsafe_depth > 0;
        let hit: Option<(&'static str, Risk, &'static str)> = match n.as_str() {
            "set_len" if in_unsafe => Some(("set-len", Risk::High, CK_SETLEN)),
            "get_unchecked" | "get_unchecked_mut" | "unwrap_unchecked" | "unchecked_add" | "unchecked_sub" | "unchecked_mul" if in_unsafe => Some(("unchecked", Risk::Medium, CK_UNCHECKED)),
            "offset" | "add" | "sub" | "byte_add" | "byte_offset" | "offset_from" if in_unsafe && is_ptr_like_receiver(&m.receiver) => Some(("ptr-arith", Risk::Medium, CK_PTR)),
            "read_unaligned" | "write_unaligned" | "copy_to" | "copy_from" | "copy_to_nonoverlapping" | "copy_from_nonoverlapping" | "read_volatile" | "write_volatile" | "write_bytes" | "drop_in_place" if in_unsafe => Some(("ptr-read-write", Risk::Medium, CK_PTR)),
            "as_ref" | "as_mut" if in_unsafe && is_ptr_like_receiver(&m.receiver) => Some(("ptr-deref", Risk::Medium, CK_PTR)),
            "assume_init" | "assume_init_ref" | "assume_init_mut" | "assume_init_read" if in_unsafe => Some(("uninit", Risk::Medium, CK_UNINIT)),
            "into_raw" | "into_raw_parts" | "leak" => Some(("ownership-to-raw", Risk::Low, CK_TO_RAW)),
            "as_ptr" if receiver_is_temporary_cstring(&m.receiver) => Some(("dangling-cstring", Risk::High, CK_DANGLING)),
            _ => None,
        };
        if let Some((kind, risk, ck)) = hit {
            self.push(span, kind, risk, format!("{}.{n}(..)", compact(&*m.receiver)), ck);
        }
        visit::visit_expr_method_call(self, m);
    }

    fn visit_expr_cast(&mut self, c: &'ast syn::ExprCast) {
        if let syn::Type::Ptr(p) = &*c.ty {
            let src = compact(&*c.expr);
            if p.mutability.is_some() && (src.ends_with("as_ptr()") || src.contains("*const")) {
                self.push(c.as_token.span, "const-to-mut", Risk::High, format!("{src} as {}", compact(&*c.ty)), CK_CONST_MUT);
            } else {
                self.push(c.as_token.span, "ptr-cast", Risk::Low, format!("{src} as {}", compact(&*c.ty)), CK_CAST);
            }
        }
        visit::visit_expr_cast(self, c);
    }

    fn visit_expr_unary(&mut self, u: &'ast syn::ExprUnary) {
        // `*p` inside unsafe where p looks like a raw pointer expression
        if self.unsafe_depth > 0 {
            if let syn::UnOp::Deref(_) = u.op {
                if let syn::Expr::Cast(c) = &*u.expr {
                    if matches!(&*c.ty, syn::Type::Ptr(_)) {
                        self.push(c.as_token.span, "ptr-deref", Risk::Medium, format!("*{}", compact(&*u.expr)), CK_PTR);
                    }
                } else if let syn::Expr::Paren(p) = &*u.expr {
                    if matches!(&*p.expr, syn::Expr::Cast(_) | syn::Expr::MethodCall(_)) {
                        self.push(p.paren_token.span.join(), "ptr-deref", Risk::Medium, format!("*{}", compact(&*u.expr)), CK_PTR);
                    }
                }
            }
        }
        visit::visit_expr_unary(self, u);
    }
}

fn is_ptr_like_receiver(e: &syn::Expr) -> bool {
    // without types we accept any receiver except integer literals / ranges
    !matches!(e, syn::Expr::Lit(_) | syn::Expr::Range(_))
}

fn receiver_is_temporary_cstring(e: &syn::Expr) -> bool {
    // CString::new(..).unwrap().as_ptr() / .expect(..).as_ptr()
    let mut cur = e;
    loop {
        match cur {
            syn::Expr::MethodCall(m) if m.method == "unwrap" || m.method == "expect" => cur = &m.receiver,
            syn::Expr::Try(t) => cur = &t.expr,
            syn::Expr::Call(c) => {
                if let syn::Expr::Path(p) = &*c.func {
                    let s = path_str(&p.path);
                    return s.ends_with("CString::new") || s.ends_with("CString::from_vec_unchecked");
                }
                return false;
            }
            _ => return false,
        }
    }
}

pub fn scan_source(file: &str, src: &str) -> Result<(Vec<Finding>, Vec<Export>), String> {
    scan_source_opts(file, src, false)
}

pub fn scan_source_opts(file: &str, src: &str, include_tests: bool) -> Result<(Vec<Finding>, Vec<Export>), String> {
    let ast = syn::parse_file(src).map_err(|e| format!("{file}: {e}"))?;
    let mut s = Scanner::new(file);
    s.include_tests = include_tests;
    s.visit_file(&ast);
    s.findings.sort_by(|a, b| a.line.cmp(&b.line).then(a.kind.cmp(b.kind)));
    Ok((s.findings, s.exports))
}

/// Scan a crate. When `src/lib.rs` or `src/main.rs` (or `src/bin/*.rs`)
/// exist, only files reachable through `mod` declarations are analysed
/// (that is the code that gets compiled); otherwise every `.rs` under `root`
/// except `target/` and hidden dirs. Test code (`#[cfg(test)]` modules,
/// `#[test]` fns, and `tests/`, `benches/`, `examples/`) is skipped unless
/// `include_tests`.
pub fn scan_dir(root: &Path) -> Report {
    scan_dir_opts(root, false)
}

fn all_rs(root: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            let n = e.file_name().to_string_lossy();
            e.depth() == 0 || !(n == "target" || n.starts_with('.'))
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|x| x == "rs"))
        .map(|e| e.into_path())
        .collect();
    files.sort();
    files
}

/// Out-of-line `mod x;` declarations of a file, resolved to paths.
fn child_modules(file: &Path, ast: &syn::File, include_tests: bool) -> Vec<PathBuf> {
    let stem = file.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let dir = file.parent().unwrap_or(Path::new("."));
    // directory where children of this file live
    let base = if matches!(stem.as_str(), "mod" | "lib" | "main") {
        dir.to_path_buf()
    } else {
        dir.join(&stem)
    };
    let mut out = vec![];
    fn walk(items: &[syn::Item], base: &Path, dir: &Path, include_tests: bool, out: &mut Vec<PathBuf>) {
        for it in items {
            if let syn::Item::Mod(m) = it {
                if !include_tests && is_test_code(&m.attrs) {
                    continue;
                }
                let name = m.ident.to_string();
                // #[path = ".."] and every #[cfg_attr(.., path = "..")] alternative
                let mut paths: Vec<String> = vec![];
                for a in &m.attrs {
                    if a.path().is_ident("path") {
                        if let syn::Meta::NameValue(nv) = &a.meta {
                            if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) = &nv.value {
                                paths.push(s.value());
                            }
                        }
                    } else if a.path().is_ident("cfg_attr") {
                        let toks: Vec<proc_macro2::TokenTree> = a.meta.to_token_stream().into_iter().collect();
                        if let Some(proc_macro2::TokenTree::Group(g)) = toks.last() {
                            let inner: Vec<proc_macro2::TokenTree> = g.stream().into_iter().collect();
                            for w in inner.windows(3) {
                                if let (proc_macro2::TokenTree::Ident(i), proc_macro2::TokenTree::Punct(p), proc_macro2::TokenTree::Literal(l)) = (&w[0], &w[1], &w[2]) {
                                    if i == "path" && p.as_char() == '=' {
                                        paths.push(l.to_string().trim_matches('"').to_string());
                                    }
                                }
                            }
                        }
                    }
                }
                let path_attr = if paths.is_empty() { None } else { Some(paths) };
                match &m.content {
                    None => {
                        if let Some(ps) = path_attr {
                            for p in ps {
                                out.push(dir.join(p));
                            }
                            // the default file may also exist for other cfgs
                            let a = base.join(format!("{name}.rs"));
                            let b = base.join(&name).join("mod.rs");
                            if a.exists() {
                                out.push(a);
                            } else if b.exists() {
                                out.push(b);
                            }
                        } else {
                            let a = base.join(format!("{name}.rs"));
                            let b = base.join(&name).join("mod.rs");
                            out.push(if a.exists() { a } else { b });
                        }
                    }
                    Some((_, inner)) => {
                        let nb = base.join(&name);
                        walk(inner, &nb, &nb, include_tests, out);
                    }
                }
            } else if let syn::Item::Macro(m) = it {
                // `mod x;` inside item macros such as cfg_if! { .. }
                let mut names = vec![];
                macro_mods(m.mac.tokens.clone(), &mut names);
                for name in names {
                    let a = base.join(format!("{name}.rs"));
                    let b = base.join(&name).join("mod.rs");
                    out.push(if a.exists() { a } else { b });
                }
            }
        }
    }
    fn macro_mods(ts: proc_macro2::TokenStream, out: &mut Vec<String>) {
        let toks: Vec<proc_macro2::TokenTree> = ts.into_iter().collect();
        for (i, t) in toks.iter().enumerate() {
            match t {
                proc_macro2::TokenTree::Group(g) => macro_mods(g.stream(), out),
                proc_macro2::TokenTree::Ident(id) if id == "mod" => {
                    if let (Some(proc_macro2::TokenTree::Ident(n)), Some(proc_macro2::TokenTree::Punct(p))) = (toks.get(i + 1), toks.get(i + 2)) {
                        if p.as_char() == ';' {
                            out.push(n.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    walk(&ast.items, &base, dir, include_tests, &mut out);
    out
}

pub fn scan_dir_opts(root: &Path, include_tests: bool) -> Report {
    let mut rep = Report { root: root.display().to_string(), ..Default::default() };
    rep.crate_name = crate_name(root);
    let mut entries: Vec<PathBuf> = vec![];
    for e in ["src/lib.rs", "src/main.rs"] {
        if root.join(e).is_file() {
            entries.push(root.join(e));
        }
    }
    if let Ok(rd) = std::fs::read_dir(root.join("src/bin")) {
        let mut bins: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "rs")).collect();
        bins.sort();
        entries.extend(bins);
    }
    if include_tests {
        for d in ["tests", "benches", "examples"] {
            entries.extend(all_rs(&root.join(d)));
        }
    }
    let use_tree = !entries.is_empty();
    let mut queue: std::collections::VecDeque<PathBuf> = if use_tree { entries.into() } else { all_rs(root).into() };
    let mut seen = std::collections::HashSet::new();
    while let Some(path) = queue.pop_front() {
        let canon = path.canonicalize().unwrap_or(path.clone());
        if !seen.insert(canon) {
            continue;
        }
        let rel = path.strip_prefix(root).unwrap_or(&path).display().to_string();
        let Ok(src) = std::fs::read_to_string(&path) else {
            rep.parse_errors.push(format!("{rel}: missing or not UTF-8"));
            continue;
        };
        rep.files_scanned += 1;
        let ast = match syn::parse_file(&src) {
            Ok(a) => a,
            Err(e) => {
                rep.parse_errors.push(format!("{rel}: {e}"));
                continue;
            }
        };
        if use_tree {
            for c in child_modules(&path, &ast, include_tests) {
                queue.push_back(c);
            }
        }
        let mut s = Scanner::new(&rel);
        s.include_tests = include_tests;
        s.visit_file(&ast);
        s.findings.sort_by(|a, b| a.line.cmp(&b.line).then(a.kind.cmp(b.kind)));
        rep.findings.extend(s.findings);
        rep.exports.extend(s.exports);
    }
    if use_tree {
        rep.not_in_module_tree = all_rs(root)
            .into_iter()
            .filter(|p| !seen.contains(&p.canonicalize().unwrap_or(p.clone())))
            .map(|p| p.strip_prefix(root).unwrap_or(&p).display().to_string())
            .collect();
    }
    rep
}

/// `[lib] name` or `[package] name` of `<root>/Cargo.toml`, with `-` -> `_`.
pub fn crate_name(root: &Path) -> Option<String> {
    let txt = std::fs::read_to_string(root.join("Cargo.toml")).ok()?;
    let mut section = String::new();
    let (mut pkg, mut lib) = (None, None);
    for line in txt.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            section = l.to_string();
            continue;
        }
        if let Some(rest) = l.strip_prefix("name") {
            let rest = rest.trim_start();
            if let Some(v) = rest.strip_prefix('=') {
                let v = v.trim().trim_matches('"').to_string();
                if section == "[package]" && pkg.is_none() {
                    pkg = Some(v);
                } else if section == "[lib]" {
                    lib = Some(v);
                }
            }
        }
    }
    lib.or(pkg).map(|n| n.replace('-', "_"))
}

fn is_simple_ffi_type(ty: &str) -> bool {
    let t = ty.trim();
    t.starts_with("*const") || t.starts_with("*mut")
        || matches!(t, "u8" | "i8" | "u16" | "i16" | "u32" | "i32" | "u64" | "i64" | "usize" | "isize" | "f32" | "f64" | "bool"
            | "c_int" | "c_uint" | "c_long" | "c_ulong" | "c_char" | "c_uchar" | "size_t" | "libc::c_int" | "libc::size_t"
            | "std::os::raw::c_int" | "std::os::raw::c_char" | "core::ffi::c_int" | "core::ffi::c_char")
}

fn arg_for(ty: &str, nonzero: bool) -> String {
    let t = ty.trim();
    if t.starts_with("*const") {
        "::core::ptr::null()".into()
    } else if t.starts_with("*mut") {
        "::core::ptr::null_mut()".into()
    } else if t == "bool" {
        "false".into()
    } else if t == "f32" || t == "f64" {
        "0.0".into()
    } else if nonzero {
        "16 as _".into()
    } else {
        "0 as _".into()
    }
}

/// Generates an integration test file that calls every exported
/// `#[no_mangle]` function whose parameters are all scalars or raw pointers,
/// with NULL pointers and 0 / 16 for integers. Run it under miri
/// (`cargo +nightly miri test`) or ASan. It encodes one contract only: an
/// exported C API must not exhibit UB when handed NULL.
pub fn generate_tests(rep: &Report) -> (String, Vec<String>) {
    let mut out = String::from(
        "// Generated by ffi-review. Contract under test: exported C functions must\n// reject NULL pointers instead of dereferencing them. Run under\n// `cargo +nightly miri test` or AddressSanitizer.\n#![allow(non_snake_case, unused_imports, clippy::all)]\nuse std::ffi::*;\n\n",
    );
    let mut skipped = vec![];
    let mut decls = String::new();
    let mut tests = String::new();
    let mut seen = std::collections::HashSet::new();
    for e in &rep.exports {
        if !seen.insert(e.symbol.clone()) {
            continue;
        }
        if !e.params.iter().all(|p| is_simple_ffi_type(&p.ty)) || !e.ret.as_deref().map(is_simple_ffi_type).unwrap_or(true) {
            skipped.push(format!("{} ({}:{}): non-scalar signature", e.symbol, e.file, e.line));
            continue;
        }
        let params: Vec<String> = e.params.iter().enumerate().map(|(i, p)| format!("a{i}: {}", p.ty)).collect();
        let ret = e.ret.as_ref().map(|r| format!(" -> {r}")).unwrap_or_default();
        decls.push_str(&format!("    fn {}({}){};\n", e.symbol, params.join(", "), ret));
        let has_ptr = e.params.iter().any(|p| p.ty.contains('*'));
        let variants: &[bool] = if has_ptr && e.params.iter().any(|p| !p.ty.contains('*')) { &[false, true] } else { &[false] };
        for &nz in variants {
            let args: Vec<String> = e.params.iter().map(|p| arg_for(&p.ty, nz)).collect();
            let suffix = if nz { "null_len16" } else { "null_zero" };
            tests.push_str(&format!(
                "#[test]\nfn ffi_review_{}_{}() {{\n    unsafe {{\n        let _ = {}({});\n    }}\n}}\n\n",
                e.symbol, suffix, e.symbol, args.join(", ")
            ));
        }
    }
    if let Some(c) = &rep.crate_name {
        // link the library so its #[no_mangle] symbols resolve (needed by miri)
        out.push_str(&format!("extern crate {c};\n\n"));
    }
    if !decls.is_empty() {
        out.push_str(&format!("extern \"C\" {{\n{decls}}}\n\n"));
    }
    out.push_str(&tests);
    (out, skipped)
}

pub fn render_markdown(rep: &Report, top: usize) -> String {
    let mut s = format!("# ffi-review report: {}\n\n", rep.root);
    let count = |r: Risk| rep.findings.iter().filter(|f| f.risk == r).count();
    s.push_str(&format!(
        "files scanned: {} (not in module tree, skipped: {}) | parse errors: {} | findings: {} (high {}, medium {}, low {}) | exported C symbols: {}\n\n",
        rep.files_scanned, rep.not_in_module_tree.len(), rep.parse_errors.len(), rep.findings.len(), count(Risk::High), count(Risk::Medium), count(Risk::Low), rep.exports.len()
    ));
    s.push_str("## Ranking by function (sum of risk weights: high=3, medium=2, low=1)\n\n| # | function | file | score | findings | max risk |\n|---|---|---|---|---|---|\n");
    for (i, f) in rep.ranking().iter().take(top).enumerate() {
        s.push_str(&format!("| {} | `{}` | {} | {} | {} | {:?} |\n", i + 1, f.function, f.file, f.score, f.findings, f.max_risk));
    }
    s.push_str("\n## Findings (high and medium)\n\n");
    for f in rep.findings.iter().filter(|f| f.risk >= Risk::Medium) {
        s.push_str(&format!("- **{:?}** `{}` {}:{} in `{}`: `{}`\n  - review: {}\n", f.risk, f.kind, f.file, f.line, f.function, f.detail, f.checklist));
    }
    if !rep.parse_errors.is_empty() {
        s.push_str("\n## Parse errors (files NOT analysed)\n\n");
        for e in &rep.parse_errors {
            s.push_str(&format!("- {e}\n"));
        }
    }
    s
}
