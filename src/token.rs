// src/token.rs
//
// The Xeres token set. Derives:
//   - Clone:     the parser holds `current_token` + `peek_token` and shifts them.
//   - PartialEq: the parser compares tokens directly (e.g. `== Token::LBrace`).
//   - Debug:     handy for diagnostics / `--dump-tokens`.

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // --- literals & identifiers ---
    Identifier(String),
    Int(i64),
    Float(f64),
    Str(String),

    // --- keywords ---
    Server,     // server
    Ui,         // ui
    Secret,     // secret   (field marker: opts a field OUT of crossing the wire)
    Synced,     // synced
    Local,      // local
    Model,      // model
    State,      // state
    Declassify, // declassify  (reserved: the single audited downgrade)
    Raw,        // raw  (the single audited un-escaped HTML sink in a view)
    Auth,       // auth  (server-fn modifier: must consult `session` — R24)
    Await,      // await  (suspend on a server-fn RPC, browser-side only)
    Try,        // try   (handle a failed await/RPC, browser-side only)
    Catch,      // catch
    Bind,       // bind  (two-way bind an input to a state cell)
    NoneLit,    // none  (the empty Optional)
    Fn,         // fn
    Let,        // let
    Return,     // return
    True,       // true
    False,      // false

    // --- operators & punctuation ---
    Assign, // =
    Eq,     // ==
    NotEq,  // !=
    Bang,   // !
    Colon,  // :
    Question, // ?  (ternary: cond ? a : b)
    Comma,  // ,
    Dot,    // .
    DotDot, // ..  (range: for i in 0..n)
    Arrow,  // ->
    Plus,   // +
    Minus,  // -
    Star,   // *
    Slash,  // /
    LAngle, // <
    RAngle, // >
    LtEq,   // <=
    GtEq,   // >=
    And,    // &&
    Or,     // ||
    LBrace,   // {
    RBrace,   // }
    LParen,   // (
    RParen,   // )
    LBracket, // [
    RBracket, // ]

    // --- control ---
    Illegal,
    EOF,

    /// A `// …` line comment, including the leading `//`. Only ever produced when
    /// the lexer is built with `keep_comments` (used by `xeres fmt`); the normal
    /// compile path skips comments at the lexer, so the parser never sees this.
    Comment(String),
}
