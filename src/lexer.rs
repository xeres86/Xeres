// src/lexer.rs
use crate::token::Token;

pub struct Lexer {
    input: Vec<char>,
    position: usize,
    read_position: usize,
    ch: char,
    line: usize,      // 1-based line of `ch`
    col: usize,       // 1-based column of `ch`
    tok_line: usize,  // line where the most recent token started
    tok_col: usize,   // column where the most recent token started
    /// When set, `//` comments are returned as `Token::Comment` instead of being
    /// skipped. Off by default, so the compile path (parser) is unchanged; only
    /// `xeres fmt` turns it on (it needs comments to preserve them).
    keep_comments: bool,
}

impl Lexer {
    pub fn new(input: &str) -> Self {
        let mut lexer = Lexer {
            input: input.chars().collect(),
            position: 0,
            read_position: 0,
            ch: '\0',
            line: 1,
            col: 0,
            tok_line: 1,
            tok_col: 1,
            keep_comments: false,
        };
        lexer.read_char();
        lexer
    }

    /// Builder: produce `Token::Comment` tokens instead of skipping comments.
    /// Used by `xeres fmt`; the compile path keeps the default (skip).
    pub fn keep_comments(mut self) -> Self {
        self.keep_comments = true;
        self
    }

    fn read_char(&mut self) {
        if self.ch == '\n' {
            self.line += 1;
            self.col = 0;
        }
        if self.read_position >= self.input.len() {
            self.ch = '\0';
        } else {
            self.ch = self.input[self.read_position];
        }
        self.position = self.read_position;
        self.read_position += 1;
        self.col += 1;
    }

    fn skip_whitespace(&mut self) {
        while self.ch.is_whitespace() {
            self.read_char();
        }
    }

    /// Line where the most recently returned token began.
    pub fn token_line(&self) -> usize { self.tok_line }
    /// Column where the most recently returned token began.
    pub fn token_col(&self) -> usize { self.tok_col }

    pub fn next_token(&mut self) -> Token {
        self.skip_whitespace();
        self.tok_line = self.line;
        self.tok_col = self.col;

        let token = match self.ch {
            '=' => {
                if self.peek_char() == '=' { self.read_char(); Token::Eq } else { Token::Assign }
            }
            ':' => Token::Colon,
            '?' => Token::Question,
            ',' => Token::Comma,
            '.' => {
                if self.peek_char() == '.' { self.read_char(); Token::DotDot } else { Token::Dot }
            }
            '{' => Token::LBrace,
            '}' => Token::RBrace,
            '(' => Token::LParen,
            ')' => Token::RParen,
            '[' => Token::LBracket,
            ']' => Token::RBracket,
            '+' => Token::Plus,
            '*' => Token::Star,
            '<' => {
                if self.peek_char() == '=' { self.read_char(); Token::LtEq } else { Token::LAngle }
            }
            '>' => {
                if self.peek_char() == '=' { self.read_char(); Token::GtEq } else { Token::RAngle }
            }
            '!' => {
                if self.peek_char() == '=' { self.read_char(); Token::NotEq } else { Token::Bang }
            }
            '&' => {
                if self.peek_char() == '&' { self.read_char(); Token::And } else { Token::Illegal }
            }
            '|' => {
                if self.peek_char() == '|' { self.read_char(); Token::Or } else { Token::Illegal }
            }
            '-' => {
                if self.peek_char() == '>' { self.read_char(); Token::Arrow } else { Token::Minus }
            }
            '/' => {
                if self.peek_char() == '/' {
                    let start = self.position;
                    while self.ch != '\n' && self.ch != '\0' { self.read_char(); }
                    if self.keep_comments {
                        let text: String = self.input[start..self.position].iter().collect();
                        return Token::Comment(text.trim_end().to_string());
                    }
                    return self.next_token();
                } else {
                    Token::Slash
                }
            }
            '"' => return Token::Str(self.read_string()),
            '\0' => Token::EOF,
            _ => {
                if self.ch.is_alphabetic() || self.ch == '_' {
                    let ident = self.read_identifier();
                    return self.lookup_keyword(&ident);
                } else if self.ch.is_ascii_digit() {
                    return self.read_number();
                } else {
                    Token::Illegal
                }
            }
        };

        self.read_char();
        token
    }

    fn read_identifier(&mut self) -> String {
        let start = self.position;
        while self.ch.is_alphabetic() || self.ch == '_' || self.ch.is_ascii_digit() {
            self.read_char();
        }
        self.input[start..self.position].iter().collect()
    }

    fn read_number(&mut self) -> Token {
        let start = self.position;
        while self.ch.is_ascii_digit() {
            self.read_char();
        }
        if self.ch == '.' && self.peek_char().is_ascii_digit() {
            self.read_char();
            while self.ch.is_ascii_digit() {
                self.read_char();
            }
            let s: String = self.input[start..self.position].iter().collect();
            Token::Float(s.parse().unwrap_or(0.0))
        } else {
            let s: String = self.input[start..self.position].iter().collect();
            Token::Int(s.parse().unwrap_or(0))
        }
    }

    fn read_string(&mut self) -> String {
        self.read_char();
        let start = self.position;
        while self.ch != '"' && self.ch != '\0' {
            self.read_char();
        }
        let s: String = self.input[start..self.position].iter().collect();
        self.read_char();
        s
    }

    fn peek_char(&self) -> char {
        if self.read_position >= self.input.len() { '\0' } else { self.input[self.read_position] }
    }

    fn lookup_keyword(&self, ident: &str) -> Token {
        match ident {
            "server" => Token::Server,
            "ui" => Token::Ui,
            "secret" => Token::Secret,
            "synced" => Token::Synced,
            "local" => Token::Local,
            "model" => Token::Model,
            "state" => Token::State,
            "declassify" => Token::Declassify,
            "raw" => Token::Raw,
            "auth" => Token::Auth,
            "await" => Token::Await,
            "try" => Token::Try,
            "catch" => Token::Catch,
            "bind" => Token::Bind,
            "none" => Token::NoneLit,
            "fn" => Token::Fn,
            "let" => Token::Let,
            "return" => Token::Return,
            "true" => Token::True,
            "false" => Token::False,
            _ => Token::Identifier(ident.to_string()),
        }
    }
}
