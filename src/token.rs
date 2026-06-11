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
    Await,      // await  (suspend on a server-fn RPC, browser-side only)
    Bind,       // bind  (two-way bind an input to a state cell)
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
    Comma,  // ,
    Dot,    // .
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
    LBrace, // {
    RBrace, // }
    LParen, // (
    RParen, // )

    // --- control ---
    Illegal,
    EOF,
}
