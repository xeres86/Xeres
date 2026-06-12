// src/parser.rs
use crate::token::Token;
use crate::lexer::Lexer;

// --- AST Structures ---

#[derive(Debug)]
pub struct ModelProperty {
    pub name: String,
    pub data_type: String,
    pub is_secret: bool,
    pub line: usize,
}

#[derive(Debug)]
pub struct ModelNode {
    pub name: String,
    pub properties: Vec<ModelProperty>,
    pub line: usize,
}

impl ModelNode {
    pub fn field(&self, name: &str) -> Option<&ModelProperty> {
        self.properties.iter().find(|p| p.name == name)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum EnvModifier { Server, Ui, None }

#[derive(Debug)]
pub struct Param {
    pub name: String,
    pub type_name: String,
}

#[derive(Debug, Clone, Copy)]
pub enum UnOp { Neg, Not }

#[derive(Debug, Clone, Copy)]
pub enum BinOp { Add, Sub, Mul, Div, Eq, NotEq, Lt, Gt, LtEq, GtEq, And, Or }

#[derive(Debug)]
pub enum Expr {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Ident(String),
    Field { base: Box<Expr>, field: String },
    Call { callee: String, args: Vec<Expr> },
    Unary { op: UnOp, expr: Box<Expr> },
    Binary { op: BinOp, left: Box<Expr>, right: Box<Expr> },
    Declassify(Box<Expr>),
    Await(Box<Expr>),
    MethodCall { receiver: Box<Expr>, method: String, args: Vec<Expr> },
    Record { name: String, fields: Vec<(String, Expr)> },
    NoneLit,
    ListLit(Vec<Expr>),
    /// `cond ? then : otherwise` — a conditional (ternary) expression.
    Ternary { cond: Box<Expr>, then: Box<Expr>, otherwise: Box<Expr> },
    /// `start..end` — a half-open integer range (used by `for i in 0..n`).
    Range { start: Box<Expr>, end: Box<Expr> },
}

#[derive(Debug)]
pub enum Stmt {
    /// `let name = expr`, or `let name: Type = expr`. The annotation lets a
    /// server-side `db.query_one(...)` bind its row onto a model (it's the only
    /// place the target model is otherwise unknown).
    Let { name: String, type_ann: Option<String>, value: Expr },
    Assign { name: String, value: Expr },
    Return(Expr),
    Expr(Expr),
    Try { body: Vec<Stmt>, handler: Vec<Stmt> },
    /// `if cond { ... } else { ... }` — statement form (the ternary is the
    /// expression form). `else_body` is empty when there's no `else`.
    If { cond: Expr, then_body: Vec<Stmt>, else_body: Vec<Stmt> },
    /// `for var in iter { ... }` — iterate a `List<T>` or a `start..end` range.
    For { var: String, iter: Expr, body: Vec<Stmt> },
    /// `while cond { ... }`.
    While { cond: Expr, body: Vec<Stmt> },
    Break,
    Continue,
    /// `match expr { Variant -> { ... } _ -> { ... } }` over an enum.
    Match { scrutinee: Expr, arms: Vec<MatchArm> },
}

#[derive(Debug)]
pub struct MatchArm {
    pub pattern: MatchPat,
    pub body: Vec<Stmt>,
}

#[derive(Debug)]
pub enum MatchPat {
    /// a bare enum variant name (the enum is known from the scrutinee)
    Variant(String),
    /// `_`
    Wildcard,
}

#[derive(Debug)]
pub struct FunctionNode {
    pub env: EnvModifier,
    pub name: String,
    pub params: Vec<Param>,
    pub return_type: Option<String>,
    pub body: Vec<Stmt>,
    pub line: usize,
}

#[derive(Debug)]
pub struct SyncedStateNode {
    pub name: String,
    pub collection_type: String,
    pub line: usize,
}

/// A click handler: either a reference/call to a fn, or an inline block.
#[derive(Debug)]
pub enum Handler {
    Call(Expr),
    Block(Vec<Stmt>),
}

#[derive(Debug)]
pub enum ViewNode {
    Element {
        tag: String,
        arg: Option<Expr>,        // positional arg, e.g. heading "Title", text x.y
        style: Option<Expr>,      // `style "css..."` — inline CSS (usually a string)
        bind: Option<String>,     // `bind stateVar` — two-way input binding
        event: Option<Handler>,   // `-> handler` or `-> { stmts }`
        children: Vec<ViewNode>,
    },
    For {
        var: String,
        iter: Expr,
        body: Vec<ViewNode>,
    },
    If {
        cond: Expr,
        then_body: Vec<ViewNode>,
        else_body: Vec<ViewNode>,
    },
    /// Invoke a reusable component by name with named args:
    /// `StatCard { title: "Revenue" value: "$45k" }`.
    Component {
        name: String,
        args: Vec<(String, Expr)>,
        line: usize,
    },
}

/// A client-side reactive state cell: `state count: Int = 0`.
#[derive(Debug)]
pub struct StateDecl {
    pub name: String,
    pub type_name: String,
    pub init: Expr,
    pub line: usize,
}

#[derive(Debug)]
pub struct ScreenNode {
    pub name: String,
    pub params: Vec<Param>,
    pub states: Vec<StateDecl>,
    pub body: Vec<ViewNode>,
    pub line: usize,
    /// `ui component` (reusable, invoked by name) vs `ui screen` (a page that
    /// auto-mounts). Both share the same typed-view machinery.
    pub is_component: bool,
}

/// `enum Name { Variant1 Variant2 ... }` — a closed set of unit variants.
/// String-backed end to end (wire/db = the variant name).
#[derive(Debug)]
pub struct EnumNode {
    pub name: String,
    pub variants: Vec<String>,
    pub line: usize,
}

#[derive(Debug)]
pub struct XeresProgram {
    pub models: Vec<ModelNode>,
    pub enums: Vec<EnumNode>,
    pub functions: Vec<FunctionNode>,
    pub states: Vec<SyncedStateNode>,
    pub screens: Vec<ScreenNode>,
}

// --- The Parser ---

pub struct Parser<'a> {
    lexer: &'a mut Lexer,
    current_token: Token,
    peek_token: Token,
    cur_line: usize,
    cur_col: usize,
    peek_line: usize,
    peek_col: usize,
    /// Whether `Name { ... }` may be parsed as a record literal here. On inside
    /// statement expressions; off in views, where `{` opens a child block.
    allow_record: bool,
}

impl<'a> Parser<'a> {
    pub fn new(lexer: &'a mut Lexer) -> Self {
        let mut parser = Parser {
            lexer,
            current_token: Token::EOF,
            peek_token: Token::EOF,
            cur_line: 1, cur_col: 1, peek_line: 1, peek_col: 1,
            allow_record: false,
        };
        parser.next_token();
        parser.next_token();
        parser
    }

    fn next_token(&mut self) {
        self.current_token = self.peek_token.clone();
        self.cur_line = self.peek_line;
        self.cur_col = self.peek_col;
        self.peek_token = self.lexer.next_token();
        self.peek_line = self.lexer.token_line();
        self.peek_col = self.lexer.token_col();
    }

    pub fn parse_program(&mut self) -> XeresProgram {
        let mut program = XeresProgram {
            models: vec![], enums: vec![], functions: vec![], states: vec![], screens: vec![],
        };

        while self.current_token != Token::EOF {
            // `enum` is a contextual keyword (top-level only).
            if self.cur_is_kw("enum") {
                if let Some(e) = self.parse_enum() {
                    program.enums.push(e);
                }
                continue;
            }
            match self.current_token {
                Token::Model => {
                    if let Some(m) = self.parse_model() { program.models.push(m); }
                }
                Token::Ui => {
                    // `ui screen Name {…}` / `ui component Name(…) {…}` vs `ui fn name() {…}`
                    if self.peek_token == Token::Identifier("screen".to_string())
                        || self.peek_token == Token::Identifier("component".to_string())
                    {
                        if let Some(s) = self.parse_screen() { program.screens.push(s); }
                    } else if let Some(f) = self.parse_function() {
                        program.functions.push(f);
                    }
                }
                Token::Server | Token::Fn => {
                    if let Some(f) = self.parse_function() { program.functions.push(f); }
                }
                Token::Synced => {
                    if let Some(s) = self.parse_synced_state() { program.states.push(s); }
                }
                _ => self.next_token(),
            }
        }
        program
    }

    fn parse_model(&mut self) -> Option<ModelNode> {
        let model_line = self.cur_line;
        self.next_token(); // consume 'model'

        let name = match &self.current_token {
            Token::Identifier(n) => n.clone(),
            _ => return None,
        };

        self.next_token(); // move to '{'
        self.next_token(); // consume '{'

        let mut properties = Vec::new();

        while self.current_token != Token::RBrace && self.current_token != Token::EOF {
            let prop_line = self.cur_line;
            let is_secret = if self.current_token == Token::Secret {
                self.next_token();
                true
            } else { false };

            let prop_name = match &self.current_token {
                Token::Identifier(n) => n.clone(),
                _ => break,
            };

            self.next_token(); // move to ':'
            self.next_token(); // consume ':'

            let data_type = match self.parse_type() {
                Some(t) => t,
                None => break,
            };

            properties.push(ModelProperty { name: prop_name, data_type, is_secret, line: prop_line });
        }

        if self.current_token == Token::RBrace { self.next_token(); }
        Some(ModelNode { name, properties, line: model_line })
    }

    /// `enum Name { Variant1 Variant2 ... }` — variants are bare identifiers,
    /// whitespace- or comma-separated.
    fn parse_enum(&mut self) -> Option<EnumNode> {
        let line = self.cur_line;
        self.next_token(); // consume 'enum'
        let name = match &self.current_token {
            Token::Identifier(n) => n.clone(),
            _ => return None,
        };
        self.next_token(); // consume name
        if self.current_token != Token::LBrace {
            return None;
        }
        self.next_token(); // consume '{'
        let mut variants = Vec::new();
        while self.current_token != Token::RBrace && self.current_token != Token::EOF {
            match &self.current_token {
                Token::Identifier(v) => {
                    variants.push(v.clone());
                    self.next_token();
                }
                Token::Comma => self.next_token(),
                _ => break,
            }
        }
        if self.current_token == Token::RBrace {
            self.next_token();
        }
        Some(EnumNode { name, variants, line })
    }

    fn parse_function(&mut self) -> Option<FunctionNode> {
        let fn_line = self.cur_line;
        let env = match self.current_token {
            Token::Server => { self.next_token(); EnvModifier::Server }
            Token::Ui => { self.next_token(); EnvModifier::Ui }
            _ => EnvModifier::None,
        };

        if self.current_token != Token::Fn { return None; }
        self.next_token(); // consume 'fn'

        let name = match &self.current_token {
            Token::Identifier(n) => n.clone(),
            _ => return None,
        };
        self.next_token(); // consume name

        // --- params: ( ident: Type, ... ) ---
        let params = self.parse_params();

        // --- optional return type: -> Type ---
        let mut return_type = None;
        if self.current_token == Token::Arrow {
            self.next_token(); // consume '->'
            return_type = self.parse_type();
        }

        // --- body: { stmt* } ---
        let mut body = Vec::new();
        if self.current_token == Token::LBrace {
            self.next_token(); // consume '{'
            while self.current_token != Token::RBrace && self.current_token != Token::EOF {
                if let Some(stmt) = self.parse_statement() {
                    body.push(stmt);
                } else {
                    self.next_token(); // skip unparseable token (prevents infinite loop)
                }
            }
            if self.current_token == Token::RBrace { self.next_token(); }
        }

        Some(FunctionNode { env, name, params, return_type, body, line: fn_line })
    }

    /// Parse a type name: `Ident` or a one-level generic `Ident<Ident>`
    /// (e.g. `List<User>`, `Optional<String>`). Returned in string form.
    fn parse_type(&mut self) -> Option<String> {
        let base = match &self.current_token {
            Token::Identifier(t) => t.clone(),
            _ => return None,
        };
        self.next_token(); // consume base
        if self.current_token == Token::LAngle {
            self.next_token(); // consume '<'
            let inner = match &self.current_token {
                Token::Identifier(t) => t.clone(),
                _ => return None,
            };
            self.next_token(); // consume inner
            if self.current_token != Token::RAngle { return None; }
            self.next_token(); // consume '>'
            Some(format!("{}<{}>", base, inner))
        } else {
            Some(base)
        }
    }

    /// Parse an optional `( name: Type, ... )` parameter list. Returns empty
    /// if there is no opening paren. Shared by functions and screens.
    fn parse_params(&mut self) -> Vec<Param> {
        let mut params = Vec::new();
        if self.current_token == Token::LParen {
            self.next_token(); // consume '('
            while self.current_token != Token::RParen && self.current_token != Token::EOF {
                let pname = match &self.current_token {
                    Token::Identifier(n) => n.clone(),
                    _ => break,
                };
                self.next_token(); // consume name
                if self.current_token != Token::Colon { break; }
                self.next_token(); // consume ':'
                let ptype = match self.parse_type() {
                    Some(t) => t,
                    None => break,
                };
                params.push(Param { name: pname, type_name: ptype });
                if self.current_token == Token::Comma { self.next_token(); }
            }
            if self.current_token == Token::RParen { self.next_token(); }
        }
        params
    }

    /// Parse a record literal `Name { field: expr, ... }`. The caller has
    /// consumed `Name` and `current_token` is the opening `{`.
    fn parse_record(&mut self, name: String) -> Option<Expr> {
        self.next_token(); // consume '{'
        let mut fields = Vec::new();
        while self.current_token != Token::RBrace && self.current_token != Token::EOF {
            let field = match &self.current_token {
                Token::Identifier(f) => f.clone(),
                _ => break,
            };
            self.next_token(); // consume field name
            if self.current_token != Token::Colon { break; }
            self.next_token(); // consume ':'
            let value = self.parse_expr()?;
            fields.push((field, value));
            if self.current_token == Token::Comma { self.next_token(); }
        }
        if self.current_token == Token::RBrace { self.next_token(); }
        Some(Expr::Record { name, fields })
    }

    /// Parse a brace-delimited statement block: `{ stmt* }`. The caller is at `{`.
    fn parse_stmt_block(&mut self) -> Vec<Stmt> {
        let mut stmts = Vec::new();
        if self.current_token != Token::LBrace { return stmts; }
        self.next_token(); // consume '{'
        while self.current_token != Token::RBrace && self.current_token != Token::EOF {
            if let Some(s) = self.parse_statement() {
                stmts.push(s);
            } else {
                self.next_token(); // skip unparseable token (prevents infinite loop)
            }
        }
        if self.current_token == Token::RBrace { self.next_token(); }
        stmts
    }

    /// `if cond { ... } [else { ... } | else if ...]` in statement position.
    fn parse_if_stmt(&mut self) -> Option<Stmt> {
        self.next_token(); // consume 'if'
        self.allow_record = false; // the `{` after the cond opens a block
        let cond = self.parse_expr()?;
        let then_body = self.parse_stmt_block();
        let mut else_body = Vec::new();
        if matches!(&self.current_token, Token::Identifier(k) if k == "else") {
            self.next_token(); // consume 'else'
            if matches!(&self.current_token, Token::Identifier(k) if k == "if") {
                if let Some(s) = self.parse_if_stmt() {
                    else_body.push(s);
                }
            } else {
                else_body = self.parse_stmt_block();
            }
        }
        Some(Stmt::If { cond, then_body, else_body })
    }

    /// `for var in iter { ... }` in statement position (`iter` may be a range).
    fn parse_for_stmt(&mut self) -> Option<Stmt> {
        self.next_token(); // consume 'for'
        let var = match &self.current_token {
            Token::Identifier(n) => n.clone(),
            _ => return None,
        };
        self.next_token(); // consume var
        match &self.current_token {
            Token::Identifier(i) if i == "in" => self.next_token(),
            _ => return None,
        }
        self.allow_record = false;
        let iter = self.parse_expr()?;
        let body = self.parse_stmt_block();
        Some(Stmt::For { var, iter, body })
    }

    /// `match expr { Variant -> { ... } _ -> { ... } }` in statement position.
    fn parse_match_stmt(&mut self) -> Option<Stmt> {
        self.next_token(); // consume 'match'
        self.allow_record = false;
        let scrutinee = self.parse_expr()?;
        if self.current_token != Token::LBrace {
            return None;
        }
        self.next_token(); // consume '{'
        let mut arms = Vec::new();
        while self.current_token != Token::RBrace && self.current_token != Token::EOF {
            let pattern = match &self.current_token {
                Token::Identifier(p) if p == "_" => {
                    self.next_token();
                    MatchPat::Wildcard
                }
                Token::Identifier(p) => {
                    let v = p.clone();
                    self.next_token();
                    MatchPat::Variant(v)
                }
                _ => break,
            };
            if self.current_token != Token::Arrow {
                break;
            }
            self.next_token(); // consume '->'
            let body = self.parse_stmt_block();
            arms.push(MatchArm { pattern, body });
        }
        if self.current_token == Token::RBrace {
            self.next_token();
        }
        Some(Stmt::Match { scrutinee, arms })
    }

    /// `while cond { ... }` in statement position.
    fn parse_while_stmt(&mut self) -> Option<Stmt> {
        self.next_token(); // consume 'while'
        self.allow_record = false;
        let cond = self.parse_expr()?;
        let body = self.parse_stmt_block();
        Some(Stmt::While { cond, body })
    }

    fn parse_statement(&mut self) -> Option<Stmt> {
        self.allow_record = true; // statements may construct records

        // control flow (contextual keywords, like the view parser)
        if let Token::Identifier(kw) = &self.current_token {
            match kw.as_str() {
                "if" => return self.parse_if_stmt(),
                "for" => return self.parse_for_stmt(),
                "while" => return self.parse_while_stmt(),
                "match" => return self.parse_match_stmt(),
                "break" => {
                    self.next_token();
                    return Some(Stmt::Break);
                }
                "continue" => {
                    self.next_token();
                    return Some(Stmt::Continue);
                }
                _ => {}
            }
        }

        // try { ... } catch { ... }
        if self.current_token == Token::Try {
            self.next_token(); // consume 'try'
            let body = self.parse_stmt_block();
            if self.current_token != Token::Catch { return None; }
            self.next_token(); // consume 'catch'
            let handler = self.parse_stmt_block();
            return Some(Stmt::Try { body, handler });
        }

        // assignment: <ident> = <expr>
        if matches!(self.current_token, Token::Identifier(_)) && self.peek_token == Token::Assign {
            let name = match &self.current_token {
                Token::Identifier(n) => n.clone(),
                _ => unreachable!(),
            };
            self.next_token(); // consume name
            self.next_token(); // consume '='
            let value = self.parse_expr()?;
            return Some(Stmt::Assign { name, value });
        }

        match self.current_token {
            Token::Return => {
                self.next_token();
                let e = self.parse_expr()?;
                Some(Stmt::Return(e))
            }
            Token::Let => {
                self.next_token();
                let name = match &self.current_token {
                    Token::Identifier(n) => n.clone(),
                    _ => return None,
                };
                self.next_token(); // consume name
                // optional `: Type` annotation
                let type_ann = if self.current_token == Token::Colon {
                    self.next_token(); // consume ':'
                    self.parse_type()
                } else {
                    None
                };
                if self.current_token != Token::Assign { return None; }
                self.next_token(); // consume '='
                let value = self.parse_expr()?;
                Some(Stmt::Let { name, type_ann, value })
            }
            _ => {
                let e = self.parse_expr()?;
                Some(Stmt::Expr(e))
            }
        }
    }

    // --- Expression parsing (precedence climbing) ---

    fn parse_expr(&mut self) -> Option<Expr> {
        let cond = self.parse_expr_bp(0)?;
        // ternary: `cond ? then : otherwise` (lowest precedence, right-assoc).
        let e = if self.current_token == Token::Question {
            self.next_token(); // consume '?'
            let then = self.parse_expr()?;
            if self.current_token != Token::Colon {
                return None;
            }
            self.next_token(); // consume ':'
            let otherwise = self.parse_expr()?;
            Expr::Ternary {
                cond: Box::new(cond),
                then: Box::new(then),
                otherwise: Box::new(otherwise),
            }
        } else {
            cond
        };
        // range: `start..end` (half-open). Lowest precedence.
        if self.current_token == Token::DotDot {
            self.next_token(); // consume '..'
            let end = self.parse_expr_bp(0)?;
            return Some(Expr::Range { start: Box::new(e), end: Box::new(end) });
        }
        Some(e)
    }

    /// Returns (operator, binding power) for the current token, if it's infix.
    fn infix_op(&self) -> Option<(BinOp, u8)> {
        match self.current_token {
            Token::Or => Some((BinOp::Or, 1)),
            Token::And => Some((BinOp::And, 2)),
            Token::Eq => Some((BinOp::Eq, 3)),
            Token::NotEq => Some((BinOp::NotEq, 3)),
            Token::LAngle => Some((BinOp::Lt, 4)),
            Token::RAngle => Some((BinOp::Gt, 4)),
            Token::LtEq => Some((BinOp::LtEq, 4)),
            Token::GtEq => Some((BinOp::GtEq, 4)),
            Token::Plus => Some((BinOp::Add, 5)),
            Token::Minus => Some((BinOp::Sub, 5)),
            Token::Star => Some((BinOp::Mul, 6)),
            Token::Slash => Some((BinOp::Div, 6)),
            _ => None,
        }
    }

    fn parse_expr_bp(&mut self, min_bp: u8) -> Option<Expr> {
        let mut lhs = self.parse_prefix()?;
        while let Some((op, bp)) = self.infix_op() {
            if bp < min_bp { break; }
            self.next_token(); // consume operator
            let rhs = self.parse_expr_bp(bp + 1)?; // +1 => left associative
            lhs = Expr::Binary { op, left: Box::new(lhs), right: Box::new(rhs) };
        }
        Some(lhs)
    }

    fn parse_prefix(&mut self) -> Option<Expr> {
        match self.current_token {
            Token::Minus => {
                self.next_token();
                let e = self.parse_prefix()?;
                Some(Expr::Unary { op: UnOp::Neg, expr: Box::new(e) })
            }
            Token::Bang => {
                self.next_token();
                let e = self.parse_prefix()?;
                Some(Expr::Unary { op: UnOp::Not, expr: Box::new(e) })
            }
            Token::Await => {
                self.next_token();
                let e = self.parse_prefix()?;
                Some(Expr::Await(Box::new(e)))
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Option<Expr> {
        let mut e = self.parse_primary()?;
        while self.current_token == Token::Dot {
            self.next_token(); // consume '.'
            let name = match &self.current_token {
                Token::Identifier(f) => f.clone(),
                _ => break,
            };
            self.next_token(); // consume name
            if self.current_token == Token::LParen {
                // method call: receiver.name(args)
                self.next_token(); // consume '('
                let mut args = Vec::new();
                while self.current_token != Token::RParen && self.current_token != Token::EOF {
                    if let Some(a) = self.parse_expr() { args.push(a); } else { break; }
                    if self.current_token == Token::Comma { self.next_token(); }
                }
                if self.current_token == Token::RParen { self.next_token(); }
                e = Expr::MethodCall { receiver: Box::new(e), method: name, args };
            } else {
                e = Expr::Field { base: Box::new(e), field: name };
            }
        }
        Some(e)
    }

    fn parse_primary(&mut self) -> Option<Expr> {
        match &self.current_token {
            Token::Int(n) => { let v = *n; self.next_token(); Some(Expr::Int(v)) }
            Token::Float(f) => { let v = *f; self.next_token(); Some(Expr::Float(v)) }
            Token::Str(s) => { let v = s.clone(); self.next_token(); Some(Expr::Str(v)) }
            Token::True => { self.next_token(); Some(Expr::Bool(true)) }
            Token::False => { self.next_token(); Some(Expr::Bool(false)) }
            Token::Declassify => {
                self.next_token(); // consume 'declassify'
                if self.current_token != Token::LParen { return None; }
                self.next_token(); // consume '('
                let inner = self.parse_expr()?;
                if self.current_token != Token::RParen { return None; }
                self.next_token(); // consume ')'
                Some(Expr::Declassify(Box::new(inner)))
            }
            Token::NoneLit => {
                self.next_token();
                Some(Expr::NoneLit)
            }
            Token::LBracket => {
                self.next_token(); // consume '['
                let mut items = Vec::new();
                while self.current_token != Token::RBracket && self.current_token != Token::EOF {
                    if let Some(e) = self.parse_expr() { items.push(e); } else { break; }
                    if self.current_token == Token::Comma { self.next_token(); }
                }
                if self.current_token == Token::RBracket { self.next_token(); }
                Some(Expr::ListLit(items))
            }
            Token::LParen => {
                self.next_token(); // consume '('
                let inner = self.parse_expr()?;
                if self.current_token != Token::RParen { return None; }
                self.next_token(); // consume ')'
                Some(inner)
            }
            Token::Identifier(n) => {
                let name = n.clone();
                self.next_token();
                if self.current_token == Token::LParen {
                    self.next_token(); // consume '('
                    let mut args = Vec::new();
                    while self.current_token != Token::RParen && self.current_token != Token::EOF {
                        if let Some(a) = self.parse_expr() { args.push(a); } else { break; }
                        if self.current_token == Token::Comma { self.next_token(); }
                    }
                    if self.current_token == Token::RParen { self.next_token(); }
                    Some(Expr::Call { callee: name, args })
                } else if self.allow_record && self.current_token == Token::LBrace {
                    self.parse_record(name)
                } else {
                    Some(Expr::Ident(name))
                }
            }
            _ => None,
        }
    }

    // --- View / screen parsing ---

    fn parse_screen(&mut self) -> Option<ScreenNode> {
        self.allow_record = false; // in views, `{` opens a child block, not a record
        let screen_line = self.cur_line;
        self.next_token(); // consume 'ui'
        let is_component = self.cur_is_kw("component");
        self.next_token(); // consume 'screen' / 'component'

        let name = match &self.current_token {
            Token::Identifier(n) => n.clone(),
            _ => return None,
        };
        self.next_token(); // consume name

        // optional typed props: ( user: User, ... )
        let params = self.parse_params();

        if self.current_token != Token::LBrace { return None; }
        self.next_token(); // consume screen '{'

        // optional `state name: Type = expr` declarations before the view.
        let mut states = Vec::new();
        while self.current_token == Token::State {
            if let Some(s) = self.parse_state_decl() {
                states.push(s);
            } else {
                break;
            }
        }

        let mut body = Vec::new();
        // expect a `view { ... }` block
        if let Token::Identifier(k) = &self.current_token {
            if k == "view" {
                self.next_token(); // consume 'view'
                if self.current_token == Token::LBrace {
                    self.next_token(); // consume view '{'
                    body = self.parse_view_nodes();
                    if self.current_token == Token::RBrace { self.next_token(); } // close view
                }
            }
        }

        if self.current_token == Token::RBrace { self.next_token(); } // close screen
        Some(ScreenNode { name, params, states, body, line: screen_line, is_component })
    }

    fn parse_state_decl(&mut self) -> Option<StateDecl> {
        let line = self.cur_line;
        self.next_token(); // consume 'state'
        let name = match &self.current_token {
            Token::Identifier(n) => n.clone(),
            _ => return None,
        };
        self.next_token(); // consume name
        if self.current_token != Token::Colon { return None; }
        self.next_token(); // consume ':'
        let type_name = self.parse_type()?;
        if self.current_token != Token::Assign { return None; }
        self.next_token(); // consume '='
        self.allow_record = true;
        let init = self.parse_expr()?;
        self.allow_record = false;
        Some(StateDecl { name, type_name, init, line })
    }

    fn parse_if_node(&mut self) -> Option<ViewNode> {
        self.next_token(); // consume 'if'
        let cond = self.parse_expr()?;
        if self.current_token != Token::LBrace { return None; }
        self.next_token(); // consume '{'
        let then_body = self.parse_view_nodes();
        if self.current_token == Token::RBrace { self.next_token(); }

        let mut else_body = Vec::new();
        if matches!(&self.current_token, Token::Identifier(k) if k == "else") {
            self.next_token(); // consume 'else'
            if matches!(&self.current_token, Token::Identifier(k) if k == "if") {
                // else if ... -> nest another if as the single else child
                if let Some(n) = self.parse_if_node() {
                    else_body.push(n);
                }
            } else if self.current_token == Token::LBrace {
                self.next_token(); // consume '{'
                else_body = self.parse_view_nodes();
                if self.current_token == Token::RBrace { self.next_token(); }
            }
        }
        Some(ViewNode::If { cond, then_body, else_body })
    }

    fn parse_view_nodes(&mut self) -> Vec<ViewNode> {
        let mut nodes = Vec::new();
        while self.current_token != Token::RBrace && self.current_token != Token::EOF {
            if let Some(n) = self.parse_view_node() {
                nodes.push(n);
            } else {
                self.next_token(); // skip unparseable token (prevents infinite loop)
            }
        }
        nodes
    }

    fn parse_view_node(&mut self) -> Option<ViewNode> {
        if let Token::Identifier(kw) = &self.current_token {
            // for <var> in <expr> { ... }
            if kw == "for" {
                self.next_token(); // consume 'for'
                let var = match &self.current_token {
                    Token::Identifier(n) => n.clone(),
                    _ => return None,
                };
                self.next_token(); // consume var
                match &self.current_token {
                    Token::Identifier(i) if i == "in" => self.next_token(),
                    _ => return None,
                }
                let iter = self.parse_expr()?;
                if self.current_token != Token::LBrace { return None; }
                self.next_token(); // consume '{'
                let body = self.parse_view_nodes();
                if self.current_token == Token::RBrace { self.next_token(); }
                return Some(ViewNode::For { var, iter, body });
            }
            // if <cond> { ... } [else { ... } | else if ...]
            if kw == "if" {
                return self.parse_if_node();
            }
        }

        // element: tag arg? (-> handler)? { children }?
        let tag = match &self.current_token {
            Token::Identifier(n) => n.clone(),
            _ => return None,
        };
        let tag_line = self.cur_line;
        self.next_token(); // consume tag

        // A Capitalized tag is a component invocation: `Name { field: expr … }`.
        // (Lowercase tags are built-in elements; this mirrors how a Capitalized
        // `Name { … }` is a record literal in expression position.)
        if tag.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            let mut args = Vec::new();
            if self.current_token == Token::LBrace {
                self.next_token(); // consume '{'
                self.allow_record = true; // arg values may be record literals
                while self.current_token != Token::RBrace && self.current_token != Token::EOF {
                    let field = match &self.current_token {
                        Token::Identifier(f) => f.clone(),
                        _ => break,
                    };
                    self.next_token(); // consume field name
                    if self.current_token != Token::Colon { break; }
                    self.next_token(); // consume ':'
                    let val = match self.parse_expr() {
                        Some(e) => e,
                        None => break,
                    };
                    args.push((field, val));
                    if self.current_token == Token::Comma { self.next_token(); }
                }
                self.allow_record = false;
                if self.current_token == Token::RBrace { self.next_token(); }
            }
            return Some(ViewNode::Component { name: tag, args, line: tag_line });
        }

        // positional arg — but `style` is a modifier keyword, not an arg.
        let arg = if self.expr_starts() && !self.cur_is_kw("style") {
            self.parse_expr()
        } else {
            None
        };

        // `style "<css>"` — inline styling on this element (may follow an arg).
        let style = if self.cur_is_kw("style") {
            self.next_token(); // consume 'style'
            if self.expr_starts() { self.parse_expr() } else { None }
        } else {
            None
        };

        // `bind <stateVar>` — two-way input binding.
        let bind = if self.current_token == Token::Bind {
            self.next_token(); // consume 'bind'
            match &self.current_token {
                Token::Identifier(n) => {
                    let v = n.clone();
                    self.next_token();
                    Some(v)
                }
                _ => None,
            }
        } else {
            None
        };

        let event = if self.current_token == Token::Arrow {
            self.next_token(); // consume '->'
            if self.current_token == Token::LBrace {
                // inline handler block: -> { stmt* }
                self.next_token(); // consume '{'
                let mut stmts = Vec::new();
                while self.current_token != Token::RBrace && self.current_token != Token::EOF {
                    if let Some(s) = self.parse_statement() {
                        stmts.push(s);
                    } else {
                        self.next_token();
                    }
                }
                if self.current_token == Token::RBrace { self.next_token(); }
                self.allow_record = false; // parse_statement set it; views must reset
                Some(Handler::Block(stmts))
            } else {
                self.parse_expr().map(Handler::Call)
            }
        } else { None };

        let children = if self.current_token == Token::LBrace {
            self.next_token(); // consume '{'
            let c = self.parse_view_nodes();
            if self.current_token == Token::RBrace { self.next_token(); }
            c
        } else { Vec::new() };

        Some(ViewNode::Element { tag, arg, style, bind, event, children })
    }

    /// Is the current token a contextual keyword `kw` (an identifier, since
    /// these aren't reserved at the lexer level)?
    fn cur_is_kw(&self, kw: &str) -> bool {
        matches!(&self.current_token, Token::Identifier(s) if s == kw)
    }

    fn expr_starts(&self) -> bool {
        matches!(
            self.current_token,
            Token::Str(_) | Token::Int(_) | Token::Float(_) | Token::True | Token::False
                | Token::Identifier(_) | Token::LParen | Token::Minus | Token::Bang
        )
    }

    fn parse_synced_state(&mut self) -> Option<SyncedStateNode> {
        let state_line = self.cur_line;
        self.next_token(); // consume 'synced'

        if self.current_token != Token::State { return None; }
        self.next_token(); // consume 'state'

        let name = match &self.current_token {
            Token::Identifier(n) => n.clone(),
            _ => return None,
        };
        self.next_token();

        if self.current_token != Token::Colon { return None; }
        self.next_token();

        if let Token::Identifier(col) = &self.current_token {
            if col != "Collection" { return None; }
        } else { return None; }
        self.next_token();

        if self.current_token != Token::LAngle { return None; }
        self.next_token();

        let collection_type = match &self.current_token {
            Token::Identifier(t) => t.clone(),
            _ => return None,
        };
        self.next_token();

        if self.current_token != Token::RAngle { return None; }
        self.next_token();

        Some(SyncedStateNode { name, collection_type, line: state_line })
    }
}
