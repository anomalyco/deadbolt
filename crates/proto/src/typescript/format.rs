//! Lays out what ts-rs renders on one line as the extension's TypeScript
//! does: an object's members one to a line, a long union one variant to a
//! line, `T[]` for `Array<T>`, doc comments indented with what they
//! describe, no semicolons.

/// One declaration, `type Name = ...` as ts-rs renders it, with its docs.
pub(super) fn declaration(docs: Option<&str>, decl: &str) -> String {
    let mut out = String::new();
    if let Some(docs) = docs {
        out.push_str(&comment(docs, ""));
        out.push('\n');
    }
    let decl = decl.trim().trim_end_matches(';');
    let (head, body) = decl.split_once(" = ").unwrap_or((decl, ""));
    let rendered = render(&Parser::new(body).ty(), "");
    out.push_str("export ");
    out.push_str(head);
    out.push_str(" =");
    if !rendered.starts_with('\n') {
        out.push(' ');
    }
    out.push_str(&rendered);
    out.push('\n');
    out
}

enum Ty {
    Union(Vec<Ty>),
    Intersection(Vec<Ty>),
    Object(Vec<Member>),
    /// A name with its type arguments, if any.
    Named(String, Vec<Ty>),
    /// A string literal, as written.
    Literal(String),
}

struct Member {
    docs: Option<String>,
    name: String,
    optional: bool,
    ty: Ty,
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Comment(String),
    Str(String),
    Word(String),
    Punct(char),
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
}

fn word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '$'
}

impl Parser {
    fn new(text: &str) -> Self {
        let mut tokens = Vec::new();
        let mut chars = text.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            match c {
                c if c.is_whitespace() => {}
                '/' if text[i..].starts_with("/**") => {
                    let end = text[i..].find("*/").map_or(text.len(), |e| i + e + 2);
                    tokens.push(Token::Comment(text[i..end].to_owned()));
                    while chars.next_if(|(j, _)| *j < end).is_some() {}
                }
                '"' => {
                    let mut s = String::from('"');
                    for (_, c) in chars.by_ref() {
                        s.push(c);
                        if c == '"' {
                            break;
                        }
                    }
                    tokens.push(Token::Str(s));
                }
                c if word_char(c) => {
                    let mut s = String::from(c);
                    while let Some((_, c)) = chars.next_if(|(_, c)| word_char(*c)) {
                        s.push(c);
                    }
                    tokens.push(Token::Word(s));
                }
                c => tokens.push(Token::Punct(c)),
            }
        }
        Self { tokens, at: 0 }
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.at).cloned();
        self.at += 1;
        token
    }

    fn eat(&mut self, c: char) -> bool {
        let found = self.tokens.get(self.at) == Some(&Token::Punct(c));
        if found {
            self.at += 1;
        }
        found
    }

    fn ty(&mut self) -> Ty {
        let mut parts = vec![self.intersection()];
        while self.eat('|') {
            parts.push(self.intersection());
        }
        if parts.len() == 1 {
            parts.remove(0)
        } else {
            Ty::Union(parts)
        }
    }

    fn intersection(&mut self) -> Ty {
        let mut parts = vec![self.primary()];
        while self.eat('&') {
            parts.push(self.primary());
        }
        if parts.len() == 1 {
            parts.remove(0)
        } else {
            Ty::Intersection(parts)
        }
    }

    fn primary(&mut self) -> Ty {
        match self.next() {
            Some(Token::Punct('{')) => self.object(),
            Some(Token::Str(s)) => Ty::Literal(s),
            Some(Token::Word(name)) => {
                let mut args = Vec::new();
                if self.eat('<') {
                    loop {
                        args.push(self.ty());
                        if !self.eat(',') {
                            break;
                        }
                    }
                    self.eat('>');
                }
                Ty::Named(name, args)
            }
            other => panic!("unexpected {other:?} in a ts-rs declaration"),
        }
    }

    fn object(&mut self) -> Ty {
        let mut members = Vec::new();
        let mut docs = None;
        loop {
            match self.next() {
                Some(Token::Punct('}')) | None => return Ty::Object(members),
                Some(Token::Punct(',')) => {}
                Some(Token::Comment(c)) => docs = Some(c),
                Some(Token::Word(name) | Token::Str(name)) => {
                    let optional = self.eat('?');
                    self.eat(':');
                    let ty = self.ty();
                    let name = match name.strip_prefix('"').and_then(|n| n.strip_suffix('"')) {
                        Some(bare) if bare.chars().all(word_char) => bare.to_owned(),
                        _ => name,
                    };
                    members.push(Member {
                        docs: docs.take(),
                        name,
                        optional,
                        ty,
                    });
                }
                Some(other) => panic!("unexpected {other:?} in a ts-rs object"),
            }
        }
    }
}

/// The widest union kept on one line.
const WIDTH: usize = 100;

fn render(ty: &Ty, indent: &str) -> String {
    match ty {
        Ty::Union(parts) => {
            let joined = parts
                .iter()
                .map(|p| render(p, indent))
                .collect::<Vec<_>>()
                .join(" | ");
            if joined.len() <= WIDTH && !joined.contains('\n') {
                return joined;
            }
            let inner = format!("{indent}    ");
            parts
                .iter()
                .map(|p| format!("\n{indent}  | {}", render(p, &inner)))
                .collect()
        }
        Ty::Intersection(parts) => parts
            .iter()
            .map(|p| render(p, indent))
            .collect::<Vec<_>>()
            .join(" & "),
        Ty::Object(members) if members.is_empty() => "{}".into(),
        Ty::Object(members) => {
            let inner = format!("{indent}  ");
            let lines: Vec<String> = members
                .iter()
                .map(|m| {
                    let optional = if m.optional { "?" } else { "" };
                    format!("{}{optional}: {}", m.name, render(&m.ty, &inner))
                })
                .collect();
            if let ([line], [member]) = (lines.as_slice(), members.as_slice())
                && member.docs.is_none()
                && !line.contains('\n')
            {
                return format!("{{ {line} }}");
            }
            let mut out = String::from("{");
            for (member, line) in members.iter().zip(lines) {
                if let Some(docs) = &member.docs {
                    out.push_str(&format!("\n{inner}{}", comment(docs, &inner)));
                }
                out.push_str(&format!("\n{inner}{line}"));
            }
            out.push_str(&format!("\n{indent}}}"));
            out
        }
        Ty::Named(name, args) => match args.as_slice() {
            [] => name.clone(),
            [element @ (Ty::Named(..) | Ty::Literal(_))] if name == "Array" => {
                format!("{}[]", render(element, indent))
            }
            args => {
                let args: Vec<String> = args.iter().map(|a| render(a, indent)).collect();
                format!("{name}<{}>", args.join(", "))
            }
        },
        Ty::Literal(s) => s.clone(),
    }
}

/// A doc comment as JSDoc at `indent` (its first line unindented): one line
/// when it is one, and rustdoc's links as plain code.
fn comment(docs: &str, indent: &str) -> String {
    let lines: Vec<String> = docs
        .lines()
        .map(|l| {
            let l = l
                .trim()
                .trim_start_matches("/**")
                .trim_end_matches("*/")
                .trim();
            l.strip_prefix('*').unwrap_or(l).trim().to_owned()
        })
        .filter(|l| !l.is_empty())
        .map(|l| {
            l.replace("[`", "`")
                .replace("`]", "`")
                .replace("crate::daemon::", "")
        })
        .collect();
    if let [line] = lines.as_slice() {
        return format!("/** {line} */");
    }
    let mut out = String::from("/**");
    for line in &lines {
        out.push_str(&format!("\n{indent} * {line}"));
    }
    out.push_str(&format!("\n{indent} */"));
    out
}
