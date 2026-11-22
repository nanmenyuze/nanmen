//! 常用 jq 表达式子集（无外部 jq 二进制依赖）。
//!
//! 目标不是假装支持完整 jq，而是覆盖广告/信息流模块里实际会用的写法：
//! 路径、`.[]`、管道、逗号、`map/select/del`、比较、算术、`if`、`//`、
//! `to_entries/from_entries`、`sort_by/unique_by`、字符串与编码函数。
//!
//! 多输出按 jq 的流语义执行；作为 HTTP 正文结果时，单个输出写该 JSON，
//! 多个输出写数组（避免丢结果）。语法/类型错误一律返回 Err，由调用方保留原正文。

use serde_json::{Map, Value};
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Dot,
    Question,
    Pipe,
    Alt,
    Comma,
    Colon,
    Semi,
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Eq,
    Update,
    PlusEq,
    MinusEq,
    EqEq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Ident(String),
    Str(String),
    Num(f64),
    At(String),
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let b: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '#' {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            continue;
        }
        // `.` 与数字小数点分开：只有 `.` 后面紧跟数字时才作为数字开头。
        if c == '.' {
            if i + 1 < b.len() && b[i + 1].is_ascii_digit() {
                let (n, ni) = lex_number(&b, i)?;
                out.push(Tok::Num(n));
                i = ni;
            } else {
                out.push(Tok::Dot);
                i += 1;
            }
            continue;
        }
        if c == '?' {
            out.push(Tok::Question);
            i += 1;
            continue;
        }
        if c == '|' {
            if i + 1 < b.len() && b[i + 1] == '|' {
                out.push(Tok::Alt);
                i += 2;
            } else if i + 1 < b.len() && b[i + 1] == '=' {
                out.push(Tok::Update);
                i += 2;
            } else {
                out.push(Tok::Pipe);
                i += 1;
            }
            continue;
        }
        if c == '/' {
            if i + 1 < b.len() && b[i + 1] == '/' {
                out.push(Tok::Alt);
                i += 2;
            } else {
                out.push(Tok::Slash);
                i += 1;
            }
            continue;
        }
        if c == '=' {
            if i + 1 < b.len() && b[i + 1] == '=' {
                out.push(Tok::EqEq);
                i += 2;
            } else {
                out.push(Tok::Eq);
                i += 1;
            }
            continue;
        }
        if c == '+' {
            if i + 1 < b.len() && b[i + 1] == '=' {
                out.push(Tok::PlusEq);
                i += 2;
            } else {
                out.push(Tok::Plus);
                i += 1;
            }
            continue;
        }
        if c == '-' {
            if i + 1 < b.len() && b[i + 1] == '=' {
                out.push(Tok::MinusEq);
                i += 2;
            } else {
                out.push(Tok::Minus);
                i += 1;
            }
            continue;
        }
        if c == '*' {
            out.push(Tok::Star);
            i += 1;
            continue;
        }
        if c == '%' {
            out.push(Tok::Percent);
            i += 1;
            continue;
        }
        if c == '!' {
            if i + 1 < b.len() && b[i + 1] == '=' {
                out.push(Tok::Ne);
                i += 2;
            } else {
                return Err("不支持的 ! 运算符".into());
            }
            continue;
        }
        if c == '<' {
            if i + 1 < b.len() && b[i + 1] == '=' {
                out.push(Tok::Le);
                i += 2;
            } else {
                out.push(Tok::Lt);
                i += 1;
            }
            continue;
        }
        if c == '>' {
            if i + 1 < b.len() && b[i + 1] == '=' {
                out.push(Tok::Ge);
                i += 2;
            } else {
                out.push(Tok::Gt);
                i += 1;
            }
            continue;
        }
        match c {
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            ':' => {
                out.push(Tok::Colon);
                i += 1;
            }
            ';' => {
                out.push(Tok::Semi);
                i += 1;
            }
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '[' => {
                out.push(Tok::LBracket);
                i += 1;
            }
            ']' => {
                out.push(Tok::RBracket);
                i += 1;
            }
            '{' => {
                out.push(Tok::LBrace);
                i += 1;
            }
            '}' => {
                out.push(Tok::RBrace);
                i += 1;
            }
            '"' => {
                let (s, ni) = lex_string(&b, i)?;
                out.push(Tok::Str(s));
                i = ni;
            }
            '@' => {
                let mut j = i + 1;
                let start = j;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == '_') {
                    j += 1;
                }
                if j == start {
                    return Err("不完整的 @ 函数".into());
                }
                out.push(Tok::At(b[start..j].iter().collect()));
                i = j;
            }
            _ if c.is_ascii_digit() => {
                let (n, ni) = lex_number(&b, i)?;
                out.push(Tok::Num(n));
                i = ni;
            }
            _ if c.is_alphabetic() || c == '_' => {
                let mut j = i + 1;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == '_') {
                    j += 1;
                }
                let word: String = b[i..j].iter().collect();
                out.push(Tok::Ident(word));
                i = j;
            }
            _ => return Err(format!("不支持的字符 {c}")),
        }
    }
    Ok(out)
}

fn lex_number(b: &[char], start: usize) -> Result<(f64, usize), String> {
    let mut i = start;
    if i < b.len() && b[i] == '-' {
        i += 1;
    }
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i < b.len() && b[i] == '.' {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    }
    if i < b.len() && (b[i] == 'e' || b[i] == 'E') {
        i += 1;
        if i < b.len() && (b[i] == '+' || b[i] == '-') {
            i += 1;
        }
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    }
    let text: String = b[start..i].iter().collect();
    let n = text
        .parse::<f64>()
        .map_err(|_| format!("数字非法: {text}"))?;
    Ok((n, i))
}

fn lex_string(b: &[char], start: usize) -> Result<(String, usize), String> {
    let mut i = start + 1;
    let mut out = String::new();
    while i < b.len() {
        match b[i] {
            '"' => return Ok((out, i + 1)),
            '\\' => {
                i += 1;
                if i >= b.len() {
                    return Err("字符串转义不完整".into());
                }
                match b[i] {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'b' => out.push('\x08'),
                    'f' => out.push('\x0c'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        if i + 4 >= b.len() {
                            return Err("Unicode 转义不完整".into());
                        }
                        let hex: String = b[i + 1..i + 5].iter().collect();
                        let code = u16::from_str_radix(&hex, 16)
                            .map_err(|_| "Unicode 转义非法".to_string())?;
                        if let Some(ch) = char::from_u32(code as u32) {
                            out.push(ch);
                        }
                        i += 4;
                    }
                    other => out.push(other),
                }
                i += 1;
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    Err("字符串未闭合".into())
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum AssignOp {
    Set,
    Update,
    Add,
    Sub,
}

#[derive(Debug, Clone, PartialEq)]
enum Step {
    Key(String),
    Index(i64),
    Iterate,
    Slice(Option<i64>, Option<i64>),
}

#[derive(Debug, Clone)]
enum Expr {
    Identity,
    Literal(Value),
    Field(Box<Expr>, String),
    Index(Box<Expr>, i64),
    Slice(Box<Expr>, Option<i64>, Option<i64>),
    Iterate(Box<Expr>),
    Optional(Box<Expr>),
    Pipe(Box<Expr>, Box<Expr>),
    Comma(Vec<Expr>),
    Array(Vec<Expr>),
    Object(Vec<(String, Expr)>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
    If(Box<Expr>, Box<Expr>, Box<Expr>),
    Call(String, Vec<Expr>),
    Assign(Vec<Step>, AssignOp, Box<Expr>),
    At(String),
}

struct Parser {
    t: Vec<Tok>,
    i: usize,
}

impl Parser {
    fn new(t: Vec<Tok>) -> Self {
        Self { t, i: 0 }
    }
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }
    fn eat(&mut self) -> Option<Tok> {
        let v = self.t.get(self.i).cloned();
        if v.is_some() {
            self.i += 1;
        }
        v
    }
    fn expect(&mut self, tok: Tok) -> Result<(), String> {
        if self.eat() == Some(tok.clone()) {
            Ok(())
        } else {
            Err(format!("期望 {tok:?}"))
        }
    }
    fn ident(&mut self) -> Option<String> {
        match self.eat() {
            Some(Tok::Ident(s)) => Some(s),
            _ => None,
        }
    }

    fn parse(mut self) -> Result<Expr, String> {
        let e = self.parse_assign()?;
        if self.i != self.t.len() {
            return Err(format!("表达式末尾有多余 token: {:?}", self.peek()));
        }
        Ok(e)
    }

    fn parse_assign(&mut self) -> Result<Expr, String> {
        let left = self.parse_pipe()?;
        let op = match self.peek() {
            Some(Tok::Eq) => Some(AssignOp::Set),
            Some(Tok::Update) => Some(AssignOp::Update),
            Some(Tok::PlusEq) => Some(AssignOp::Add),
            Some(Tok::MinusEq) => Some(AssignOp::Sub),
            _ => None,
        };
        if let Some(op) = op {
            self.eat();
            let path = expr_path(&left).ok_or_else(|| "赋值左侧必须是路径".to_string())?;
            let right = self.parse_assign()?;
            return Ok(Expr::Assign(path, op, Box::new(right)));
        }
        Ok(left)
    }

    fn parse_pipe(&mut self) -> Result<Expr, String> {
        let mut e = self.parse_comma()?;
        while self.peek() == Some(&Tok::Pipe) || self.peek() == Some(&Tok::Semi) {
            self.eat();
            let r = self.parse_comma()?;
            e = Expr::Pipe(Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    fn parse_comma(&mut self) -> Result<Expr, String> {
        let mut v = vec![self.parse_alt()?];
        while self.peek() == Some(&Tok::Comma) {
            self.eat();
            v.push(self.parse_alt()?);
        }
        Ok(if v.len() == 1 {
            v.pop().unwrap()
        } else {
            Expr::Comma(v)
        })
    }

    fn parse_alt(&mut self) -> Result<Expr, String> {
        let mut e = self.parse_or()?;
        while self.peek() == Some(&Tok::Alt) {
            self.eat();
            let r = self.parse_or()?;
            e = Expr::Binary(BinOp::Or, Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut e = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Ident(s)) if s == "or") {
            self.eat();
            let r = self.parse_and()?;
            e = Expr::Binary(BinOp::Or, Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut e = self.parse_cmp()?;
        while matches!(self.peek(), Some(Tok::Ident(s)) if s == "and") {
            self.eat();
            let r = self.parse_cmp()?;
            e = Expr::Binary(BinOp::And, Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    fn parse_cmp(&mut self) -> Result<Expr, String> {
        let mut e = self.parse_add()?;
        loop {
            let op = match self.peek() {
                Some(Tok::EqEq) => Some(BinOp::Eq),
                Some(Tok::Ne) => Some(BinOp::Ne),
                Some(Tok::Lt) => Some(BinOp::Lt),
                Some(Tok::Le) => Some(BinOp::Le),
                Some(Tok::Gt) => Some(BinOp::Gt),
                Some(Tok::Ge) => Some(BinOp::Ge),
                _ => None,
            };
            let Some(op) = op else { break };
            self.eat();
            let r = self.parse_add()?;
            e = Expr::Binary(op, Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    fn parse_add(&mut self) -> Result<Expr, String> {
        let mut e = self.parse_mul()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Plus) => Some(BinOp::Add),
                Some(Tok::Minus) => Some(BinOp::Sub),
                _ => None,
            };
            let Some(op) = op else { break };
            self.eat();
            let r = self.parse_mul()?;
            e = Expr::Binary(op, Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    fn parse_mul(&mut self) -> Result<Expr, String> {
        let mut e = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Star) => Some(BinOp::Mul),
                Some(Tok::Slash) => Some(BinOp::Div),
                Some(Tok::Percent) => Some(BinOp::Mod),
                _ => None,
            };
            let Some(op) = op else { break };
            self.eat();
            let r = self.parse_unary()?;
            e = Expr::Binary(op, Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    fn parse_unary(&mut self) -> Result<Expr, String> {
        if self.peek() == Some(&Tok::Minus) {
            self.eat();
            return Ok(Expr::Neg(Box::new(self.parse_unary()?)));
        }
        if matches!(self.peek(), Some(Tok::Ident(s)) if s == "not") {
            self.eat();
            return Ok(Expr::Call("not".into(), vec![]));
        }
        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Result<Expr, String> {
        let mut e = self.parse_primary()?;
        loop {
            match self.peek() {
                Some(Tok::Dot) => {
                    self.eat();
                    match self.eat() {
                        Some(Tok::Ident(name)) => e = Expr::Field(Box::new(e), name),
                        Some(Tok::Str(name)) => e = Expr::Field(Box::new(e), name),
                        Some(Tok::LBracket) => {
                            self.eat();
                            self.expect(Tok::RBracket)?;
                            e = Expr::Iterate(Box::new(e));
                            continue;
                        }
                        other => return Err(format!("字段名非法: {other:?}")),
                    }
                }
                Some(Tok::LBracket) => {
                    self.eat();
                    if self.peek() == Some(&Tok::RBracket) {
                        self.eat();
                        e = Expr::Iterate(Box::new(e));
                        continue;
                    }
                    let first = self.parse_index_value()?;
                    if self.peek() == Some(&Tok::Colon) {
                        self.eat();
                        let second = self.parse_index_value()?;
                        self.expect(Tok::RBracket)?;
                        e = Expr::Slice(Box::new(e), first, second);
                    } else {
                        self.expect(Tok::RBracket)?;
                        let Some(n) = first else {
                            return Err("数组索引必须是整数".into());
                        };
                        e = Expr::Index(Box::new(e), n);
                    }
                }
                Some(Tok::Question) => {
                    self.eat();
                    e = Expr::Optional(Box::new(e));
                }
                _ => break,
            }
        }
        Ok(e)
    }

    fn parse_index_value(&mut self) -> Result<Option<i64>, String> {
        let sign = if self.peek() == Some(&Tok::Minus) {
            self.eat();
            -1
        } else {
            1
        };
        match self.eat() {
            Some(Tok::Num(n)) if n.fract() == 0.0 => Ok(Some((n as i64) * sign)),
            Some(Tok::Ident(s)) => Err(format!("不支持的索引 {s}")),
            Some(Tok::RBracket) => {
                self.i -= 1;
                Ok(None)
            }
            other => Err(format!("索引非法: {other:?}")),
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.eat() {
            Some(Tok::Dot) => {
                if let Some(Tok::Ident(name)) = self.peek().cloned() {
                    self.eat();
                    Ok(Expr::Field(Box::new(Expr::Identity), name))
                } else {
                    Ok(Expr::Identity)
                }
            }
            Some(Tok::Num(n)) => Ok(Expr::Literal(num_value(n))),
            Some(Tok::Str(s)) => Ok(Expr::Literal(Value::String(s))),
            Some(Tok::At(name)) => Ok(Expr::At(name)),
            Some(Tok::LBracket) => {
                let mut items = Vec::new();
                if self.peek() != Some(&Tok::RBracket) {
                    loop {
                        items.push(self.parse_assign()?);
                        if self.peek() == Some(&Tok::Comma) {
                            self.eat();
                        } else {
                            break;
                        }
                    }
                }
                self.expect(Tok::RBracket)?;
                Ok(Expr::Array(items))
            }
            Some(Tok::LBrace) => {
                let mut items = Vec::new();
                if self.peek() != Some(&Tok::RBrace) {
                    loop {
                        let key = match self.eat() {
                            Some(Tok::Ident(s)) => s,
                            Some(Tok::Str(s)) => s,
                            other => return Err(format!("对象键非法: {other:?}")),
                        };
                        let value = if self.peek() == Some(&Tok::Colon) {
                            self.eat();
                            self.parse_assign()?
                        } else {
                            Expr::Field(Box::new(Expr::Identity), key.clone())
                        };
                        items.push((key, value));
                        if self.peek() == Some(&Tok::Comma) {
                            self.eat();
                        } else {
                            break;
                        }
                    }
                }
                self.expect(Tok::RBrace)?;
                Ok(Expr::Object(items))
            }
            Some(Tok::LParen) => {
                let e = self.parse_assign()?;
                self.expect(Tok::RParen)?;
                Ok(e)
            }
            Some(Tok::Ident(word)) => {
                match word.as_str() {
                    "true" => return Ok(Expr::Literal(Value::Bool(true))),
                    "false" => return Ok(Expr::Literal(Value::Bool(false))),
                    "null" => return Ok(Expr::Literal(Value::Null)),
                    "if" => return self.parse_if(),
                    "empty" => return Ok(Expr::Call("empty".into(), vec![])),
                    _ => {}
                }
                if self.peek() == Some(&Tok::LParen) {
                    self.eat();
                    let mut args = Vec::new();
                    if self.peek() != Some(&Tok::RParen) {
                        loop {
                            args.push(self.parse_assign()?);
                            if self.peek() == Some(&Tok::Comma) {
                                self.eat();
                            } else {
                                break;
                            }
                        }
                    }
                    self.expect(Tok::RParen)?;
                    Ok(Expr::Call(word, args))
                } else {
                    Ok(Expr::Call(word, vec![]))
                }
            }
            other => Err(format!("表达式开头非法: {other:?}")),
        }
    }

    fn parse_if(&mut self) -> Result<Expr, String> {
        let cond = self.parse_assign()?;
        if !matches!(self.peek(), Some(Tok::Ident(s)) if s == "then") {
            return Err("if 缺少 then".into());
        }
        self.eat();
        let yes = self.parse_assign()?;
        let no = if matches!(self.peek(), Some(Tok::Ident(s)) if s == "else") {
            self.eat();
            self.parse_assign()?
        } else {
            Expr::Literal(Value::Null)
        };
        if matches!(self.peek(), Some(Tok::Ident(s)) if s == "end") {
            self.eat();
        } else {
            return Err("if 缺少 end".into());
        }
        Ok(Expr::If(Box::new(cond), Box::new(yes), Box::new(no)))
    }
}

fn expr_path(e: &Expr) -> Option<Vec<Step>> {
    match e {
        Expr::Identity => Some(Vec::new()),
        Expr::Field(base, name) => {
            let mut p = expr_path(base)?;
            p.push(Step::Key(name.clone()));
            Some(p)
        }
        Expr::Index(base, n) => {
            let mut p = expr_path(base)?;
            p.push(Step::Index(*n));
            Some(p)
        }
        Expr::Iterate(base) => {
            let mut p = expr_path(base)?;
            p.push(Step::Iterate);
            Some(p)
        }
        _ => None,
    }
}

pub fn validate(expr: &str) -> Result<(), String> {
    let e = expr.trim();
    if e.is_empty() {
        return Err("jq 表达式为空".into());
    }
    Parser::new(lex(e)?).parse().map(|_| ())
}

fn truthy(v: &Value) -> bool {
    !matches!(v, Value::Null | Value::Bool(false))
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn as_i64(v: &Value) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    v.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)
}

fn compare(a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x
            .as_f64()
            .partial_cmp(&y.as_f64())
            .unwrap_or(Ordering::Equal),
        (Value::String(x), Value::String(y)) => x.cmp(y),
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        (Value::Null, Value::Null) => Ordering::Equal,
        _ => type_name(a).cmp(type_name(b)),
    }
}

fn num_value(n: f64) -> Value {
    if n.is_finite() && n.fract() == 0.0 && n >= i64::MIN as f64 && n <= i64::MAX as f64 {
        Value::from(n as i64)
    } else {
        Value::from(n)
    }
}

fn json_add(a: &Value, b: &Value) -> Option<Value> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            let x = x.as_f64()?;
            let y = y.as_f64()?;
            Some(num_value(x + y))
        }
        (Value::String(x), Value::String(y)) => Some(Value::String(format!("{x}{y}"))),
        (Value::Array(x), Value::Array(y)) => {
            let mut out = x.clone();
            out.extend(y.clone());
            Some(Value::Array(out))
        }
        (Value::Object(x), Value::Object(y)) => {
            let mut out = x.clone();
            for (k, v) in y {
                out.insert(k.clone(), v.clone());
            }
            Some(Value::Object(out))
        }
        (Value::Null, x) => Some(x.clone()),
        (x, Value::Null) => Some(x.clone()),
        _ => None,
    }
}

fn json_sub(a: &Value, b: &Value) -> Option<Value> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => Some(num_value(x.as_f64()? - y.as_f64()?)),
        (Value::Array(x), Value::Array(y)) => Some(Value::Array(
            x.iter().filter(|v| !y.contains(v)).cloned().collect(),
        )),
        _ => None,
    }
}

fn json_mul(a: &Value, b: &Value) -> Option<Value> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => Some(num_value(x.as_f64()? * y.as_f64()?)),
        (Value::String(x), Value::Number(y)) => {
            let n = y.as_f64()?;
            if n.fract() != 0.0 || n < 0.0 {
                return None;
            }
            Some(Value::String(x.repeat(n as usize)))
        }
        _ => None,
    }
}

fn json_div(a: &Value, b: &Value) -> Option<Value> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            let d = y.as_f64()?;
            if d == 0.0 {
                None
            } else {
                Some(num_value(x.as_f64()? / d))
            }
        }
        (Value::String(x), Value::String(y)) => Some(Value::Array(
            x.split(y).map(|s| Value::String(s.to_string())).collect(),
        )),
        _ => None,
    }
}

fn json_mod(a: &Value, b: &Value) -> Option<Value> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            let d = y.as_f64()?;
            if d == 0.0 {
                None
            } else {
                Some(num_value(x.as_f64()? % d))
            }
        }
        _ => None,
    }
}

fn get_path<'a>(mut v: &'a Value, path: &[Step]) -> Option<&'a Value> {
    for s in path {
        match s {
            Step::Key(k) => v = v.as_object()?.get(k)?,
            Step::Index(n) => {
                let arr = v.as_array()?;
                let idx = if *n < 0 { arr.len() as i64 + *n } else { *n };
                v = arr.get(idx as usize)?;
            }
            Step::Iterate | Step::Slice(_, _) => return None,
        }
    }
    Some(v)
}

fn set_path(v: &mut Value, path: &[Step], new: Value) -> bool {
    if path.is_empty() {
        *v = new;
        return true;
    }
    let mut cur = v;
    for (i, s) in path.iter().enumerate() {
        let last = i + 1 == path.len();
        match s {
            Step::Key(k) => {
                if !cur.is_object() {
                    *cur = Value::Object(Map::new());
                }
                let obj = cur.as_object_mut().unwrap();
                if last {
                    obj.insert(k.clone(), new);
                    return true;
                }
                if !obj.contains_key(k) {
                    obj.insert(k.clone(), Value::Null);
                }
                cur = obj.get_mut(k).unwrap();
            }
            Step::Index(n) => {
                if !cur.is_array() {
                    *cur = Value::Array(Vec::new());
                }
                let arr = cur.as_array_mut().unwrap();
                let idx = if *n < 0 { arr.len() as i64 + *n } else { *n };
                if idx < 0 {
                    return false;
                }
                while arr.len() <= idx as usize {
                    arr.push(Value::Null);
                }
                if last {
                    arr[idx as usize] = new;
                    return true;
                }
                cur = &mut arr[idx as usize];
            }
            Step::Iterate | Step::Slice(_, _) => return false,
        }
    }
    false
}

fn del_path(v: &mut Value, path: &[Step]) -> bool {
    if path.is_empty() {
        return false;
    }
    let mut cur = v;
    for (i, s) in path.iter().enumerate() {
        let last = i + 1 == path.len();
        match s {
            Step::Key(k) => {
                let Some(obj) = cur.as_object_mut() else {
                    return false;
                };
                if last {
                    return obj.remove(k).is_some();
                }
                let Some(next) = obj.get_mut(k) else {
                    return false;
                };
                cur = next;
            }
            Step::Index(n) => {
                let Some(arr) = cur.as_array_mut() else {
                    return false;
                };
                let idx = if *n < 0 { arr.len() as i64 + *n } else { *n };
                if idx < 0 || idx as usize >= arr.len() {
                    return false;
                }
                if last {
                    arr.remove(idx as usize);
                    return true;
                }
                cur = &mut arr[idx as usize];
            }
            Step::Iterate | Step::Slice(_, _) => return false,
        }
    }
    false
}

fn to_entries(v: &Value) -> Option<Value> {
    match v {
        Value::Object(o) => Some(Value::Array(
            o.iter()
                .map(|(k, v)| {
                    let mut m = Map::new();
                    m.insert("key".into(), Value::String(k.clone()));
                    m.insert("value".into(), v.clone());
                    Value::Object(m)
                })
                .collect(),
        )),
        Value::Array(a) => Some(Value::Array(
            a.iter()
                .enumerate()
                .map(|(i, v)| {
                    let mut m = Map::new();
                    m.insert("key".into(), Value::from(i));
                    m.insert("value".into(), v.clone());
                    Value::Object(m)
                })
                .collect(),
        )),
        _ => None,
    }
}

fn from_entries(v: &Value) -> Option<Value> {
    let arr = v.as_array()?;
    let mut out = Map::new();
    for item in arr {
        let o = item.as_object()?;
        let key = o.get("key").or_else(|| o.get("name"))?;
        let key = match key {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => continue,
        };
        out.insert(key, o.get("value").cloned().unwrap_or(Value::Null));
    }
    Some(Value::Object(out))
}

fn flatten(v: &Value, depth: Option<usize>) -> Value {
    fn walk(v: &Value, depth: Option<usize>, cur: usize, out: &mut Vec<Value>) {
        if let Value::Array(a) = v {
            if depth.map(|d| cur < d).unwrap_or(true) {
                for x in a {
                    walk(x, depth, cur + 1, out);
                }
            } else {
                out.push(v.clone());
            }
        } else {
            out.push(v.clone());
        }
    }
    let mut out = Vec::new();
    walk(v, depth, 0, &mut out);
    Value::Array(out)
}

fn eval(expr: &Expr, input: &Value) -> Result<Vec<Value>, String> {
    match expr {
        Expr::Identity => Ok(vec![input.clone()]),
        Expr::Literal(v) => Ok(vec![v.clone()]),
        Expr::Field(base, name) => {
            let mut out = Vec::new();
            for b in eval(base, input)? {
                if let Some(v) = b.as_object().and_then(|o| o.get(name)) {
                    out.push(v.clone());
                }
            }
            Ok(out)
        }
        Expr::Index(base, n) => {
            let mut out = Vec::new();
            for b in eval(base, input)? {
                if let Some(arr) = b.as_array() {
                    let idx = if *n < 0 { arr.len() as i64 + *n } else { *n };
                    if idx >= 0 {
                        if let Some(v) = arr.get(idx as usize) {
                            out.push(v.clone());
                        }
                    }
                }
            }
            Ok(out)
        }
        Expr::Slice(base, a, b) => {
            let mut out = Vec::new();
            for base in eval(base, input)? {
                if let Some(arr) = base.as_array() {
                    let len = arr.len() as i64;
                    let start = a.unwrap_or(0);
                    let end = b.unwrap_or(len);
                    let s = if start < 0 {
                        (len + start).max(0)
                    } else {
                        start.min(len)
                    };
                    let e = if end < 0 {
                        (len + end).max(0)
                    } else {
                        end.min(len)
                    };
                    if s < e {
                        out.push(Value::Array(arr[s as usize..e as usize].to_vec()));
                    } else {
                        out.push(Value::Array(Vec::new()));
                    }
                }
            }
            Ok(out)
        }
        Expr::Iterate(base) => {
            let mut out = Vec::new();
            for b in eval(base, input)? {
                match b {
                    Value::Array(a) => out.extend(a),
                    Value::Object(o) => out.extend(o.into_iter().map(|(_, v)| v)),
                    Value::Null => {}
                    _ => return Err(".[] 只能用于数组/对象".into()),
                }
            }
            Ok(out)
        }
        Expr::Optional(base) => Ok(eval(base, input).unwrap_or_default()),
        Expr::Pipe(l, r) => {
            let mut out = Vec::new();
            for v in eval(l, input)? {
                out.extend(eval(r, &v)?);
            }
            Ok(out)
        }
        Expr::Comma(items) => {
            let mut out = Vec::new();
            for e in items {
                out.extend(eval(e, input)?);
            }
            Ok(out)
        }
        Expr::Array(items) => {
            let mut out = Vec::new();
            for e in items {
                out.extend(eval(e, input)?);
            }
            Ok(vec![Value::Array(out)])
        }
        Expr::Object(items) => {
            let mut obj = Map::new();
            for (k, e) in items {
                let v = eval(e, input)?.into_iter().next().unwrap_or(Value::Null);
                obj.insert(k.clone(), v);
            }
            Ok(vec![Value::Object(obj)])
        }
        Expr::Binary(op, l, r) => {
            if *op == BinOp::Or {
                let lv = eval(l, input)?;
                if lv.iter().any(truthy) {
                    return Ok(lv);
                }
                return eval(r, input);
            }
            let lv = eval(l, input)?;
            let rv = eval(r, input)?;
            let mut out = Vec::new();
            for a in &lv {
                for b in &rv {
                    let v = match op {
                        BinOp::Add => json_add(a, b),
                        BinOp::Sub => json_sub(a, b),
                        BinOp::Mul => json_mul(a, b),
                        BinOp::Div => json_div(a, b),
                        BinOp::Mod => json_mod(a, b),
                        BinOp::Eq => Some(Value::Bool(a == b)),
                        BinOp::Ne => Some(Value::Bool(a != b)),
                        BinOp::Lt => Some(Value::Bool(compare(a, b) == Ordering::Less)),
                        BinOp::Le => Some(Value::Bool(compare(a, b) != Ordering::Greater)),
                        BinOp::Gt => Some(Value::Bool(compare(a, b) == Ordering::Greater)),
                        BinOp::Ge => Some(Value::Bool(compare(a, b) != Ordering::Less)),
                        BinOp::And => Some(Value::Bool(truthy(a) && truthy(b))),
                        BinOp::Or => unreachable!(),
                    };
                    out.push(v.ok_or_else(|| "jq 运算类型不匹配".to_string())?);
                }
            }
            Ok(out)
        }
        Expr::Neg(e) => {
            let mut out = Vec::new();
            for v in eval(e, input)? {
                let Some(n) = v.as_f64() else {
                    return Err("一元负号需要数字".into());
                };
                out.push(num_value(-n));
            }
            Ok(out)
        }
        Expr::If(cond, yes, no) => {
            let cv = eval(cond, input)?;
            if cv.iter().any(truthy) {
                eval(yes, input)
            } else {
                eval(no, input)
            }
        }
        Expr::Call(name, args) => call(name, args, input),
        Expr::Assign(path, op, rhs) => {
            let current = get_path(input, path).cloned().unwrap_or(Value::Null);
            let base = match op {
                AssignOp::Set => input.clone(),
                _ => current.clone(),
            };
            let rv = eval(rhs, &base)?.into_iter().next().unwrap_or(Value::Null);
            let newv = match op {
                AssignOp::Set => rv,
                AssignOp::Update => rv,
                AssignOp::Add => json_add(&current, &rv).ok_or("jq += 类型不匹配")?,
                AssignOp::Sub => json_sub(&current, &rv).ok_or("jq -= 类型不匹配")?,
            };
            let mut out = input.clone();
            if !set_path(&mut out, path, newv) {
                return Err("jq 赋值路径不可写".into());
            }
            Ok(vec![out])
        }
        Expr::At(name) => {
            let v = input;
            let s = match name.as_str() {
                "json" => serde_json::to_string(v).unwrap_or_default(),
                "text" => match v {
                    Value::String(s) => s.clone(),
                    _ => serde_json::to_string(v).unwrap_or_default(),
                },
                "uri" => urlencode(&match v {
                    Value::String(s) => s.clone(),
                    _ => serde_json::to_string(v).unwrap_or_default(),
                }),
                "base64" => {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD.encode(match v {
                        Value::String(s) => s.clone(),
                        _ => serde_json::to_string(v).unwrap_or_default(),
                    })
                }
                "csv" | "tsv" => {
                    let arr = v.as_array().ok_or("@csv/@tsv 需要数组")?;
                    let sep = if name == "tsv" { "\t" } else { "," };
                    let text = |x: &Value| match x {
                        Value::String(s) => s.clone(),
                        Value::Null => String::new(),
                        _ => serde_json::to_string(x).unwrap_or_default(),
                    };
                    arr.iter().map(text).collect::<Vec<_>>().join(sep)
                }
                _ => return Err(format!("不支持的 @{name}")),
            };
            Ok(vec![Value::String(s)])
        }
    }
}

fn urlencode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn call(name: &str, args: &[Expr], input: &Value) -> Result<Vec<Value>, String> {
    let first = |i: usize| -> Result<Vec<Value>, String> {
        let e = args.get(i).ok_or_else(|| format!("{name} 缺参数"))?;
        eval(e, input)
    };
    match name {
        "empty" => Ok(Vec::new()),
        "not" => Ok(vec![Value::Bool(!truthy(input))]),
        "length" => Ok(vec![Value::from(match input {
            Value::Array(a) => a.len(),
            Value::Object(o) => o.len(),
            Value::String(s) => s.chars().count(),
            Value::Null => 0,
            Value::Number(n) => n.as_f64().unwrap_or(0.0).abs() as usize,
            _ => 0,
        } as i64)]),
        "type" => Ok(vec![Value::String(type_name(input).into())]),
        "tostring" => Ok(vec![Value::String(match input {
            Value::String(s) => s.clone(),
            _ => serde_json::to_string(input).unwrap_or_default(),
        })]),
        "tonumber" => {
            if let Some(n) = input.as_f64() {
                return Ok(vec![Value::from(n)]);
            }
            let s = input.as_str().ok_or("tonumber 需要字符串/数字")?;
            let n = s
                .parse::<f64>()
                .map_err(|_| "tonumber 解析失败".to_string())?;
            Ok(vec![Value::from(n)])
        }
        "keys" | "keys_unsorted" => {
            let mut out = match input {
                Value::Object(o) => o.keys().cloned().map(Value::String).collect::<Vec<_>>(),
                Value::Array(a) => (0..a.len()).map(|i| Value::from(i)).collect(),
                _ => return Err(format!("{name} 需要数组/对象")),
            };
            if name == "keys" {
                out.sort_by(|a, b| compare(a, b));
            }
            Ok(vec![Value::Array(out)])
        }
        "values" => match input {
            Value::Object(o) => Ok(o.values().cloned().collect()),
            Value::Array(a) => Ok(a.clone()),
            _ => Ok(Vec::new()),
        },
        "has" | "contains" => {
            let needle = first(0)?.into_iter().next().unwrap_or(Value::Null);
            let yes = match (name, input, &needle) {
                ("has", Value::Object(o), Value::String(k)) => o.contains_key(k),
                ("has", Value::Array(a), v) => v
                    .as_i64()
                    .map(|i| i >= 0 && (i as usize) < a.len())
                    .unwrap_or(false),
                ("contains", Value::Array(a), Value::Array(b)) => b.iter().all(|x| a.contains(x)),
                ("contains", Value::String(a), Value::String(b)) => a.contains(b),
                ("contains", Value::Object(a), Value::Object(b)) => b
                    .iter()
                    .all(|(k, v)| a.get(k).map(|x| x == v).unwrap_or(false)),
                _ => false,
            };
            Ok(vec![Value::Bool(yes)])
        }
        "map" => {
            let f = args.first().ok_or("map 缺参数")?;
            let items = match input {
                Value::Array(a) => a.clone(),
                Value::Object(o) => o.values().cloned().collect(),
                Value::Null => Vec::new(),
                _ => return Err("map 需要数组/对象".into()),
            };
            let mut out = Vec::new();
            for item in &items {
                out.extend(eval(f, item)?);
            }
            Ok(vec![Value::Array(out)])
        }
        "map_values" => {
            let f = args.first().ok_or("map_values 缺参数")?;
            match input {
                Value::Array(a) => {
                    let mut out = Vec::new();
                    for item in a {
                        out.push(eval(f, item)?.into_iter().next().unwrap_or(Value::Null));
                    }
                    Ok(vec![Value::Array(out)])
                }
                Value::Object(o) => {
                    let mut out = Map::new();
                    for (k, v) in o {
                        out.insert(
                            k.clone(),
                            eval(f, v)?.into_iter().next().unwrap_or(Value::Null),
                        );
                    }
                    Ok(vec![Value::Object(out)])
                }
                _ => Err("map_values 需要数组/对象".into()),
            }
        }
        "select" => {
            let f = args.first().ok_or("select 缺参数")?;
            let yes = eval(f, input)?.iter().any(truthy);
            Ok(if yes { vec![input.clone()] } else { Vec::new() })
        }
        "del" => {
            let mut out = input.clone();
            for a in args {
                if let Some(path) = expr_path(a) {
                    let _ = del_path(&mut out, &path);
                }
            }
            // del 的逗号参数被 parser 作为多个 args 传入；这里不再处理路径表达式之外的输入。
            Ok(vec![out])
        }
        "to_entries" => to_entries(input)
            .map(|v| vec![v])
            .ok_or("to_entries 需要对象/数组".into()),
        "from_entries" => from_entries(input)
            .map(|v| vec![v])
            .ok_or("from_entries 需要数组".into()),
        "with_entries" => {
            let f = args.first().ok_or("with_entries 缺参数")?;
            let es = to_entries(input).ok_or("with_entries 需要对象")?;
            let mut arr = Vec::new();
            for e in es.as_array().unwrap() {
                arr.extend(eval(f, e)?);
            }
            from_entries(&Value::Array(arr))
                .map(|v| vec![v])
                .ok_or("with_entries 结果非法".into())
        }
        "sort" => {
            let mut a = input.as_array().cloned().ok_or("sort 需要数组")?;
            a.sort_by(compare);
            Ok(vec![Value::Array(a)])
        }
        "sort_by" => {
            let f = args.first().ok_or("sort_by 缺参数")?;
            let mut a = input.as_array().cloned().ok_or("sort_by 需要数组")?;
            let mut keyed = Vec::new();
            for item in a.drain(..) {
                let key = eval(f, &item)?.into_iter().next().unwrap_or(Value::Null);
                keyed.push((key, item));
            }
            keyed.sort_by(|(a, _), (b, _)| compare(a, b));
            Ok(vec![Value::Array(
                keyed.into_iter().map(|(_, v)| v).collect(),
            )])
        }
        "unique" => {
            let a = input.as_array().cloned().ok_or("unique 需要数组")?;
            let mut out: Vec<Value> = Vec::new();
            for v in a {
                if !out.contains(&v) {
                    out.push(v);
                }
            }
            Ok(vec![Value::Array(out)])
        }
        "unique_by" => {
            let f = args.first().ok_or("unique_by 缺参数")?;
            let a = input.as_array().cloned().ok_or("unique_by 需要数组")?;
            let mut seen = Vec::new();
            let mut out = Vec::new();
            for v in a {
                let key = eval(f, &v)?.into_iter().next().unwrap_or(Value::Null);
                if !seen.contains(&key) {
                    seen.push(key);
                    out.push(v);
                }
            }
            Ok(vec![Value::Array(out)])
        }
        "reverse" => {
            let mut a = input.as_array().cloned().ok_or("reverse 需要数组")?;
            a.reverse();
            Ok(vec![Value::Array(a)])
        }
        "flatten" => {
            let depth = first(0).ok().and_then(|v| v.first().and_then(as_i64));
            Ok(vec![flatten(input, depth.map(|d| d.max(0) as usize))])
        }
        "add" => {
            let a = input.as_array().ok_or("add 需要数组")?;
            let mut acc = Value::Null;
            for v in a {
                acc = json_add(&acc, v).ok_or("add 类型不匹配")?;
            }
            Ok(vec![acc])
        }
        "join" => {
            let sep = first(0)?
                .into_iter()
                .next()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .ok_or("join 需要分隔符")?;
            let a = input.as_array().ok_or("join 需要数组")?;
            let parts: Vec<String> = a
                .iter()
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    Value::Null => String::new(),
                    _ => serde_json::to_string(v).unwrap_or_default(),
                })
                .collect();
            Ok(vec![Value::String(parts.join(&sep))])
        }
        "split" => {
            let sep = first(0)?
                .into_iter()
                .next()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .ok_or("split 需要分隔符")?;
            let s = input.as_str().ok_or("split 需要字符串")?;
            Ok(vec![Value::Array(
                s.split(&sep).map(|x| Value::String(x.into())).collect(),
            )])
        }
        "startswith" | "endswith" => {
            let needle = first(0)?
                .into_iter()
                .next()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .ok_or("参数需要字符串")?;
            let s = input.as_str().ok_or("需要字符串")?;
            Ok(vec![Value::Bool(if name == "startswith" {
                s.starts_with(&needle)
            } else {
                s.ends_with(&needle)
            })])
        }
        "first" => match input {
            Value::Array(a) => Ok(a.first().cloned().into_iter().collect()),
            _ => Ok(vec![input.clone()]),
        },
        "last" => match input {
            Value::Array(a) => Ok(a.last().cloned().into_iter().collect()),
            _ => Ok(vec![input.clone()]),
        },
        "nth" => {
            let n = first(0)?
                .into_iter()
                .next()
                .and_then(|v| as_i64(&v))
                .ok_or("nth 需要整数")?;
            let a = input.as_array().ok_or("nth 需要数组")?;
            let idx = if n < 0 { a.len() as i64 + n } else { n };
            Ok(if idx >= 0 {
                a.get(idx as usize).cloned().into_iter().collect()
            } else {
                Vec::new()
            })
        }
        "range" => {
            let start = first(0)?
                .into_iter()
                .next()
                .and_then(|v| as_i64(&v))
                .unwrap_or(0);
            let end = args
                .get(1)
                .map(|e| eval(e, input))
                .transpose()?
                .and_then(|v| v.first().and_then(as_i64))
                .unwrap_or(start);
            let mut out = Vec::new();
            let mut i = start;
            while i < end {
                out.push(Value::from(i));
                i += 1;
            }
            Ok(out)
        }
        "ascii_downcase" | "ascii_upcase" => {
            let s = input.as_str().ok_or("需要字符串")?;
            Ok(vec![Value::String(if name == "ascii_downcase" {
                s.to_ascii_lowercase()
            } else {
                s.to_ascii_uppercase()
            })])
        }
        "ltrimstr" | "rtrimstr" => {
            let needle = first(0)?
                .into_iter()
                .next()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .ok_or("参数需要字符串")?;
            let s = input.as_str().ok_or("需要字符串")?;
            let out = if name == "ltrimstr" {
                s.strip_prefix(&needle).unwrap_or(s)
            } else {
                s.strip_suffix(&needle).unwrap_or(s)
            };
            Ok(vec![Value::String(out.to_string())])
        }
        _ => Err(format!("不支持的 jq 函数 {name}")),
    }
}

pub fn run(expr: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let parsed = Parser::new(lex(expr)?).parse()?;
    let input: Value =
        serde_json::from_slice(body).map_err(|e| format!("正文不是合法 JSON: {e}"))?;
    let out = eval(&parsed, &input)?;
    let value = match out.len() {
        0 => Value::Null,
        1 => out.into_iter().next().unwrap(),
        _ => Value::Array(out),
    };
    serde_json::to_vec(&value).map_err(|e| format!("jq 输出序列化失败: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_str(expr: &str, json: &str) -> String {
        String::from_utf8(run(expr, json.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn path_pipe_and_select() {
        let body = r#"{"data":{"items":[{"name":"a","ad":true},{"name":"b","ad":false}]}}"#;
        assert_eq!(
            run_str(".data.items | map(select(.ad | not) | .name)", body),
            r#"["b"]"#
        );
        assert_eq!(run_str(".data.items[0].name", body), r#""a""#);
    }

    #[test]
    fn iterate_and_array_build() {
        assert_eq!(
            run_str("[.items[] | .id]", r#"{"items":[{"id":1},{"id":2}]}"#),
            "[1,2]"
        );
        assert_eq!(
            run_str(
                ".items | map(.id) | add",
                r#"{"items":[{"id":1},{"id":2}]}"#
            ),
            "3"
        );
    }

    #[test]
    fn condition_and_alternative() {
        assert_eq!(
            run_str(r#"if .ok then "yes" else "no" end"#, r#"{"ok":true}"#),
            r#""yes""#
        );
        assert_eq!(run_str(r#".missing // "fallback""#, "{}"), r#""fallback""#);
    }

    #[test]
    fn arithmetic_and_assignment() {
        assert_eq!(run_str(".n + 2", r#"{"n":1}"#), "3");
        assert_eq!(run_str(".a.b = 5", r#"{"a":{}}"#), r#"{"a":{"b":5}}"#);
        assert_eq!(run_str(".a |= . + 1", r#"{"a":2}"#), r#"{"a":3}"#);
    }

    #[test]
    fn delete_and_entries() {
        assert_eq!(
            run_str("del(.a.b)", r#"{"a":{"b":1,"c":2}}"#),
            r#"{"a":{"c":2}}"#
        );
        assert_eq!(
            run_str(
                "to_entries | map(select(.value == 1)) | from_entries",
                r#"{"a":1,"b":2}"#
            ),
            r#"{"a":1}"#,
        );
    }

    #[test]
    fn string_and_encoding_functions() {
        assert_eq!(run_str("split(\",\")", r#""a,b""#), r#"["a","b"]"#);
        assert_eq!(run_str("@base64", r#"{"a":1}"#).len() > 2, true);
        assert_eq!(run_str(".s | startswith(\"x\")", r#"{"s":"xyz"}"#), "true");
    }

    #[test]
    fn invalid_is_rejected() {
        assert!(validate(".a |").is_err());
        assert!(validate("map(").is_err());
        assert!(validate(".a.b").is_ok());
    }
}
