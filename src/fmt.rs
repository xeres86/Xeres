// src/fmt.rs — `xeres fmt`, the canonical formatter.
//
// A token-stream pretty-printer: it lexes the source (keeping comments) and
// re-emits it with canonical whitespace. It deliberately does NOT go through the
// AST, because the AST buckets declarations by kind (losing source order) and
// carries no line numbers on statements/expressions/view nodes — so an
// AST-printer couldn't preserve declaration order or comments. Working from the
// token stream keeps both for free.
//
// Zero coupling to the checker/codegen. `format` is a pure function of the
// source text, so it can format a file that doesn't type-check (format-on-error),
// and re-formatting its own output is a no-op (idempotence is the correctness
// bar — see tests/fmt.rs).
//
// What it normalizes: 2-space indentation by brace depth, a single space around
// binary operators / after `:`/`,`, no space inside `()`/`[]` or around `.`/
// generics, one blank line between top-level declarations (runs collapsed),
// model/enum/endpoint members one per line, no trailing whitespace, and a single
// trailing newline. It preserves the source's line breaks for statements and
// view nodes (it won't join or force-split them) and leaves `style "css"` strings
// untouched.

use crate::frontend::lexer::Lexer;
use crate::frontend::token::Token;

/// Which kind of `{ … }` block we're inside. Member contexts (model/enum/
/// endpoint) lay their members out one-per-line; `Normal` (fn bodies, views,
/// record literals, …) preserves the source's own line breaks.
#[derive(Clone, Copy, PartialEq)]
enum Ctx {
    Normal,
    Model,
    Enum,
    Endpoint,
}

impl Ctx {
    fn is_member(self) -> bool {
        matches!(self, Ctx::Model | Ctx::Enum | Ctx::Endpoint)
    }
}

/// Canonical source text for a single token.
fn token_src(t: &Token) -> String {
    match t {
        Token::Identifier(s) => s.clone(),
        Token::Int(n) => n.to_string(),
        // Keep a Float a Float: `0.0` must not render as `0` (which lexes as an
        // Int). `{}` round-trips the value; append `.0` only if it lost the dot.
        Token::Float(f) => {
            let s = format!("{}", f);
            if s.contains('.') || s.contains('e') || s.contains('E') { s } else { format!("{}.0", s) }
        }
        Token::Str(s) => format!("\"{}\"", s),
        Token::Comment(s) => s.clone(),

        Token::Server => "server".into(),
        Token::Ui => "ui".into(),
        Token::Secret => "secret".into(),
        Token::Synced => "synced".into(),
        Token::Local => "local".into(),
        Token::Model => "model".into(),
        Token::State => "state".into(),
        Token::Declassify => "declassify".into(),
        Token::Raw => "raw".into(),
        Token::Auth => "auth".into(),
        Token::Await => "await".into(),
        Token::Try => "try".into(),
        Token::Catch => "catch".into(),
        Token::Bind => "bind".into(),
        Token::NoneLit => "none".into(),
        Token::Fn => "fn".into(),
        Token::Let => "let".into(),
        Token::Return => "return".into(),
        Token::True => "true".into(),
        Token::False => "false".into(),

        Token::Assign => "=".into(),
        Token::Eq => "==".into(),
        Token::NotEq => "!=".into(),
        Token::Bang => "!".into(),
        Token::Colon => ":".into(),
        Token::Question => "?".into(),
        Token::Comma => ",".into(),
        Token::Dot => ".".into(),
        Token::DotDot => "..".into(),
        Token::Arrow => "->".into(),
        Token::Plus => "+".into(),
        Token::Minus => "-".into(),
        Token::Star => "*".into(),
        Token::Slash => "/".into(),
        Token::LAngle => "<".into(),
        Token::RAngle => ">".into(),
        Token::LtEq => "<=".into(),
        Token::GtEq => ">=".into(),
        Token::And => "&&".into(),
        Token::Or => "||".into(),
        Token::LBrace => "{".into(),
        Token::RBrace => "}".into(),
        Token::LParen => "(".into(),
        Token::RParen => ")".into(),
        Token::LBracket => "[".into(),
        Token::RBracket => "]".into(),

        Token::Illegal | Token::EOF => String::new(),
    }
}

/// Lex the whole source into `(token, source-line)` pairs, keeping comments.
fn lex_with_lines(src: &str) -> Vec<(Token, usize)> {
    let mut lx = Lexer::new(src).keep_comments();
    let mut out = Vec::new();
    loop {
        let t = lx.next_token();
        let line = lx.token_line();
        let done = matches!(t, Token::EOF);
        out.push((t, line));
        if done {
            break;
        }
    }
    out
}

fn is_ident_or_value(t: &Token) -> bool {
    matches!(
        t,
        Token::Identifier(_)
            | Token::Int(_)
            | Token::Float(_)
            | Token::Str(_)
            | Token::True
            | Token::False
            | Token::RParen
            | Token::RBracket
    )
}

fn is_generic_head(t: &Token) -> bool {
    matches!(t, Token::Identifier(s) if s == "List" || s == "Optional")
}

/// A top-level declaration opener — gets a blank line before it (except first).
fn is_decl_start(t: &Token) -> bool {
    matches!(
        t,
        Token::Server | Token::Ui | Token::Fn | Token::Model | Token::Synced | Token::Local | Token::Auth
    ) || matches!(t, Token::Identifier(s) if s == "enum" || s == "endpoint")
}

/// Per-line spacing state (reset at the start of each output line).
struct LineState {
    prev: Option<Token>,
    /// `<…>` generic nesting depth (List/Optional only); inside it, `<`/`>`/
    /// idents get no surrounding spaces. Distinguishes generics from comparisons.
    gdepth: i32,
    /// Unconsumed `?`s on this line — the next `:` is then a ternary colon
    /// (spaced both sides) rather than a type/field colon (space after only).
    pending_q: i32,
    /// The previous token was a unary `-`/`!` prefix → no space after it.
    prev_unary: bool,
}

impl LineState {
    fn new() -> Self {
        LineState { prev: None, gdepth: 0, pending_q: 0, prev_unary: false }
    }
}

/// Whether a space goes before `cur`, given the previous token on the line and
/// the running line state. Also updates generic/ternary/unary tracking.
fn space_and_update(st: &mut LineState, cur: &Token) -> bool {
    let prev = st.prev.clone();
    let prev_unary = st.prev_unary;
    st.prev_unary = false;

    // Detect a generic-opening `<` (after List/Optional) before deciding spacing.
    let opening_generic = matches!(cur, Token::LAngle)
        && prev.as_ref().map(is_generic_head).unwrap_or(false);
    let closing_generic = matches!(cur, Token::RAngle) && st.gdepth > 0;

    let space = match prev {
        None => false, // start of line
        Some(ref p) => {
            // Inside a generic argument: no spaces at all.
            if st.gdepth > 0 && matches!(cur, Token::LAngle | Token::RAngle | Token::Identifier(_) | Token::Comma | Token::Int(_)) {
                false
            } else if opening_generic {
                false
            } else if prev_unary {
                false // no space after a unary `-`/`!`
            } else {
                no_then_yes(p, cur, st)
            }
        }
    };

    // Track ternary `?` … `:`.
    match cur {
        Token::Question => st.pending_q += 1,
        Token::Colon if st.pending_q > 0 => st.pending_q -= 1,
        _ => {}
    }
    // Track generic depth.
    if opening_generic {
        st.gdepth += 1;
    } else if closing_generic {
        st.gdepth -= 1;
    }
    // Track a unary prefix for the *next* token.
    if matches!(cur, Token::Bang) {
        st.prev_unary = true;
    } else if matches!(cur, Token::Minus) {
        let binary = prev.as_ref().map(is_ident_or_value).unwrap_or(false);
        st.prev_unary = !binary;
    }

    st.prev = Some(cur.clone());
    space
}

/// The core spacing table (called when not inside a generic / after a unary).
fn no_then_yes(prev: &Token, cur: &Token, st: &LineState) -> bool {
    // No space *before* these.
    match cur {
        Token::Comma | Token::Dot | Token::DotDot | Token::RParen | Token::RBracket => return false,
        Token::Colon => return st.pending_q > 0, // ternary colon is spaced; field colon isn't
        Token::LParen | Token::LBracket => {
            // call / index when glued to a value; otherwise (grouping / list
            // literal) it's spaced.
            return !is_ident_or_value(prev);
        }
        Token::RBrace => return !matches!(prev, Token::LBrace), // `{}` stays tight
        _ => {}
    }
    // No space *after* these.
    match prev {
        Token::Dot | Token::DotDot | Token::LParen | Token::LBracket | Token::Bang => return false,
        Token::Colon => return true, // `name: Type`
        _ => {}
    }
    true
}

struct OutLine {
    indent: usize,
    text: String,
    blank_before: bool,
}

pub fn format(src: &str) -> String {
    let toks = lex_with_lines(src);
    let mut out: Vec<OutLine> = Vec::new();

    let mut cur = String::new();
    let mut cur_indent = 0usize;
    let mut cur_blank = false;
    let mut ls = LineState::new();

    let mut depth = 0usize;
    let mut ctx: Vec<Ctx> = vec![Ctx::Normal];
    let mut pending_member: Option<Ctx> = None;
    let mut force_break = false;
    // the source line where the previous token *ended* — a multi-line string
    // (e.g. `style "…css…"`) ends below where it started, so a following `{`
    // must not look like it jumped to a new line.
    let mut prev_end = 0usize;
    let mut prev_tok: Option<Token> = None;

    for i in 0..toks.len() {
        let (t, line) = (&toks[i].0, toks[i].1);
        if matches!(t, Token::EOF) {
            break;
        }
        let next = toks.get(i + 1).map(|x| &x.0);
        let cur_ctx = *ctx.last().unwrap();
        // `{}`, `[]`, and `()` all nest indentation (so multi-line list literals
        // and arg lists indent); single-line uses net to zero, so they're inert.
        let closing = matches!(t, Token::RBrace | Token::RBracket | Token::RParen);

        // ---- decide whether to break before this token ----
        let mut do_break = false;
        let mut blank = false;
        if !cur.is_empty() {
            if force_break {
                do_break = true;
            } else if line > prev_end {
                do_break = true;
                blank = line > prev_end + 1;
            } else if cur_ctx.is_member() && member_starts_here(cur_ctx, t, next, prev_tok.as_ref()) {
                do_break = true;
            } else if cur_ctx.is_member() && matches!(t, Token::RBrace) {
                do_break = true;
            }
        }
        force_break = false;

        if do_break {
            out.push(OutLine { indent: cur_indent, text: std::mem::take(&mut cur), blank_before: cur_blank });
            cur_blank = false;
            ls = LineState::new();
        }

        // a closing brace dedents *before* its own line's indent is taken
        if closing {
            depth = depth.saturating_sub(1);
            ctx.pop();
        }

        // first token of a fresh line: fix its indent + blank-line policy.
        // A blank line precedes each top-level declaration *or its leading
        // comment block* — but never splits a comment from the decl below it,
        // and consecutive comment lines stay together (prev-token-is-comment).
        if cur.is_empty() {
            cur_indent = depth;
            let lead = depth == 0
                && !out.is_empty()
                && (is_decl_start(t) || matches!(t, Token::Comment(_)))
                && !matches!(prev_tok, Some(Token::Comment(_)));
            cur_blank = blank || lead;
        }

        // emit the token with canonical spacing
        if space_and_update(&mut ls, t) {
            cur.push(' ');
        }
        cur.push_str(&token_src(t));

        // ---- structural bookkeeping for braces ----
        if matches!(t, Token::LBrace | Token::LBracket | Token::LParen) {
            // only `{` can open a member context (model/enum/endpoint body);
            // `[`/`(` always nest as Normal.
            let nc = if matches!(t, Token::LBrace) {
                pending_member.take().unwrap_or(Ctx::Normal)
            } else {
                Ctx::Normal
            };
            ctx.push(nc);
            depth += 1;
            force_break = nc.is_member();
        } else if is_decl_start(t) && depth == 0 {
            // remember the kind so the matching `{` opens the right member ctx
            pending_member = match t {
                Token::Model => Some(Ctx::Model),
                Token::Identifier(s) if s == "enum" => Some(Ctx::Enum),
                Token::Identifier(s) if s == "endpoint" => Some(Ctx::Endpoint),
                _ => pending_member, // fn/screen/state → Normal (leave as None)
            };
        }

        let nl = if let Token::Str(s) = t { s.matches('\n').count() } else { 0 };
        prev_end = line + nl;
        prev_tok = Some(t.clone());
    }
    if !cur.is_empty() {
        out.push(OutLine { indent: cur_indent, text: cur, blank_before: cur_blank });
    }

    render(&out)
}

/// Does a new member of `ctx` begin at `t`? (model: `secret` or a `name:` field;
/// enum: each variant ident; endpoint: `base` or `secret`.)
fn member_starts_here(ctx: Ctx, t: &Token, next: Option<&Token>, prev: Option<&Token>) -> bool {
    match ctx {
        Ctx::Model => {
            matches!(t, Token::Secret)
                || (matches!(t, Token::Identifier(_))
                    && matches!(next, Some(Token::Colon))
                    && !matches!(prev, Some(Token::Secret)))
        }
        Ctx::Enum => matches!(t, Token::Identifier(_)),
        Ctx::Endpoint => matches!(t, Token::Secret) || matches!(t, Token::Identifier(s) if s == "base"),
        Ctx::Normal => false,
    }
}

fn render(lines: &[OutLine]) -> String {
    let mut s = String::new();
    for (i, l) in lines.iter().enumerate() {
        // a blank line before this one (never leading, never doubled)
        if l.blank_before && i > 0 {
            s.push('\n');
        }
        for _ in 0..l.indent {
            s.push_str("  ");
        }
        s.push_str(l.text.trim_end());
        s.push('\n');
    }
    s
}
