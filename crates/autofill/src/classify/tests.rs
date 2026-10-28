//! Hand-written snapshots of common page shapes.

use super::*;
use crate::snapshot::{Element, Field, Flags, Form};

struct Page {
    frame: Frame,
}

impl Page {
    fn new(url: &str, title: &str) -> Page {
        Page {
            frame: Frame {
                frame_ref: "0".into(),
                url: url.into(),
                title: title.into(),
                ..Frame::default()
            },
        }
    }

    fn form(mut self, text: &str) -> Page {
        let id = self.frame.forms.len() as u32;
        self.frame.forms.push(Form {
            id,
            text: text.into(),
            ..Form::default()
        });
        self
    }

    fn heading(mut self, text: &str) -> Page {
        self.frame.headings.push(text.into());
        self
    }

    /// Adds a field to the last form (or none when `in_form` is false).
    fn field(mut self, in_form: bool, f: impl FnOnce(&mut Field)) -> Page {
        let mut field = Field {
            id: self.frame.fields.len() as u32,
            form: if in_form {
                self.frame.forms.len().checked_sub(1).map(|i| i as u32)
            } else {
                None
            },
            flags: Flags {
                visible: true,
                ..Flags::default()
            },
            ..Field::default()
        };
        f(&mut field);
        self.frame.fields.push(field);
        self
    }

    fn button(self, in_form: bool, text: &str) -> Page {
        self.field(in_form, |f| {
            f.element = Element::Button;
            f.text = text.into();
            f.flags.submit = true;
        })
    }

    fn run(self) -> FrameAnalysis {
        let engine = Engine::embedded().unwrap();
        let snapshot = Snapshot {
            url: self.frame.url.clone(),
            title: self.frame.title.clone(),
            frames: vec![self.frame],
        };
        snapshot.validate().unwrap();
        engine.analyze(&snapshot).frames.remove(0)
    }
}

fn roles(f: &FrameAnalysis) -> Vec<(u32, Option<&'static str>)> {
    f.fields
        .iter()
        .map(|x| (x.id, x.role.map(FieldType::rule_name)))
        .collect()
}

#[test]
fn identifier_first_sign_in() {
    let out = Page::new("https://accounts.example.com/signin/identifier", "Sign in")
        .heading("Sign in")
        .form("Email or phone Forgot email? Next")
        .field(true, |f| {
            f.element = Element::Email;
            f.autocomplete = "username webauthn".into();
            f.aria_label = "Email or phone".into();
        })
        .button(true, "Next")
        .run();
    assert_eq!(out.kind, Some(FormKind::Login));
    assert_eq!(roles(&out), vec![(0, Some("username"))]);
}

#[test]
fn username_and_password_login() {
    let out = Page::new("https://example.com/login", "Example")
        .form("Username Password Remember me Forgot password? Sign in")
        .field(true, |f| {
            f.name = "login".into();
            f.labels = vec!["Username or email address".into()];
            f.autocomplete = "username".into();
        })
        .field(true, |f| {
            f.element = Element::Password;
            f.name = "password".into();
            f.labels = vec!["Password".into()];
        })
        .button(true, "Sign in")
        .run();
    assert_eq!(out.kind, Some(FormKind::Login));
    assert_eq!(
        roles(&out),
        vec![(0, Some("username")), (1, Some("password"))]
    );
    let password = &out.fields[1];
    assert!(
        password
            .trace
            .iter()
            .any(|c| c.rule == "password:password" && c.channel == Some(Channel::Display))
    );
    assert!(
        out.groups[0]
            .trace
            .iter()
            .any(|c| c.rule == "shape:one-password")
    );
}

#[test]
fn signup_with_confirmation() {
    let out = Page::new("https://example.com/register", "Create your account")
        .form("Create an account Email Password Confirm password I agree to the terms of service Sign up")
        .field(true, |f| {
            f.element = Element::Email;
            f.placeholder = "Email".into();
        })
        .field(true, |f| {
            f.element = Element::Password;
            f.placeholder = "Password".into();
        })
        .field(true, |f| {
            f.element = Element::Password;
            f.placeholder = "Confirm password".into();
        })
        .button(true, "Sign up")
        .run();
    assert_eq!(out.kind, Some(FormKind::Signup));
    assert_eq!(
        roles(&out),
        vec![
            (0, Some("email")),
            (1, Some("new-password")),
            (2, Some("new-password"))
        ]
    );
}

#[test]
fn change_password() {
    let out = Page::new("https://example.com/settings/security", "Settings")
        .heading("Change password")
        .form("Current password New password Confirm new password Update password")
        .field(true, |f| {
            f.element = Element::Password;
            f.labels = vec!["Current password".into()];
        })
        .field(true, |f| {
            f.element = Element::Password;
            f.labels = vec!["New password".into()];
        })
        .field(true, |f| {
            f.element = Element::Password;
            f.labels = vec!["Confirm new password".into()];
        })
        .button(true, "Update password")
        .run();
    assert_eq!(out.kind, Some(FormKind::ChangePassword));
    assert_eq!(
        roles(&out),
        vec![
            (0, Some("password")),
            (1, Some("new-password")),
            (2, Some("new-password"))
        ]
    );
}

#[test]
fn split_one_time_code() {
    let mut page = Page::new("https://example.com/verify", "Two-step verification")
        .heading("Enter the code we sent to your phone")
        .form("Enter the 6-digit code Verify");
    for _ in 0..6 {
        page = page.field(true, |f| {
            f.element = Element::Tel;
            f.max_length = Some(1);
            f.input_mode = "numeric".into();
        });
    }
    let out = page.button(true, "Verify").run();
    assert_eq!(out.kind, Some(FormKind::Mfa));
    assert_eq!(out.fields.len(), 6);
    assert!(
        out.fields
            .iter()
            .all(|f| f.role == Some(FieldType::OneTimeCode) && f.split == Some(6))
    );
}

#[test]
fn newsletter_box_is_not_a_sign_in() {
    let out = Page::new("https://shop.example.com/", "Shop")
        .form("Stay in touch Subscribe to our newsletter for 10% off Subscribe")
        .field(true, |f| {
            f.element = Element::Email;
            f.placeholder = "Your email".into();
        })
        .button(true, "Subscribe")
        .run();
    assert_eq!(out.kind, None);
    assert_eq!(out.groups[0].kind, FormKind::Newsletter);
}

#[test]
fn search_box_gets_nothing() {
    let out = Page::new("https://example.com/", "Example")
        .form("")
        .field(true, |f| {
            f.element = Element::Search;
            f.name = "q".into();
        })
        .field(false, |f| {
            f.name = "query".into();
            f.placeholder = "Search products".into();
        })
        .run();
    assert_eq!(out.kind, None);
    assert_eq!(roles(&out), vec![(0, None), (1, None)]);
}

#[test]
fn login_fields_outside_any_form_with_a_footer_newsletter() {
    let out = Page::new("https://example.com/account", "Log in")
        .heading("Log in")
        .field(false, |f| {
            f.element = Element::Email;
            f.placeholder = "Email".into();
        })
        .field(false, |f| {
            f.element = Element::Password;
            f.placeholder = "Password".into();
        })
        .button(false, "Log in")
        .form("Newsletter Subscribe")
        .field(true, |f| {
            f.element = Element::Email;
            f.placeholder = "you@example.com".into();
        })
        .run();
    assert_eq!(out.kind, Some(FormKind::Login));
    assert_eq!(out.primary_group, Some(0));
    assert_eq!(out.groups.len(), 2);
    assert_eq!(out.groups[1].kind, FormKind::Newsletter);
}

#[test]
fn analysis_is_deterministic() {
    let build = || {
        Page::new("https://example.com/login", "Sign in")
            .form("Sign in")
            .field(true, |f| f.name = "user".into())
            .field(true, |f| f.element = Element::Password)
            .run()
    };
    assert_eq!(
        serde_json::to_string(&build()).unwrap(),
        serde_json::to_string(&build()).unwrap()
    );
}

// ---- Known misses of detect.ts -------------------------------------------------

#[test]
fn tel_boxes_for_cpf_sms_codes_and_miles() {
    let cpf = Page::new("https://www.example.com.br/login", "Entrar")
        .form("Entrar CPF Senha Entrar")
        .field(true, |f| {
            f.element = Element::Tel;
            f.labels = vec!["CPF".into()];
            f.input_mode = "numeric".into();
        })
        .field(true, |f| {
            f.element = Element::Password;
            f.labels = vec!["Senha".into()];
        })
        .run();
    assert_eq!(
        roles(&cpf),
        vec![(0, Some("username")), (1, Some("password"))]
    );

    let sms = Page::new("https://www.example.com.br/verificacao", "Verificação")
        .form("Digite o código SMS que enviamos Confirmar")
        .field(true, |f| {
            f.element = Element::Tel;
            f.labels = vec!["Código SMS".into()];
        })
        .run();
    assert_eq!(roles(&sms), vec![(0, Some("otp"))]);
    assert_eq!(sms.kind, Some(FormKind::Mfa));

    let miles = Page::new("https://www.example-air.com/login", "Log in")
        .form("Log in SkyMiles number Password Log in")
        .field(true, |f| {
            f.element = Element::Tel;
            f.labels = vec!["SkyMiles Number".into()];
        })
        .field(true, |f| {
            f.element = Element::Password;
            f.labels = vec!["Password".into()];
        })
        .run();
    assert_eq!(
        roles(&miles),
        vec![(0, Some("username")), (1, Some("password"))]
    );
}

#[test]
fn pin_box_with_a_library_card_is_a_password() {
    let out = Page::new(
        "https://library.example.org/patroninfo",
        "Log in to your account",
    )
    .form("Library card number Enter your 4-digit PIN Submit")
    .field(true, |f| {
        f.name = "code".into();
        f.label_before = "Library card number".into();
    })
    .field(true, |f| {
        f.element = Element::Password;
        f.name = "pin".into();
        f.label_before = "Enter your 4-digit PIN".into();
    })
    .run();
    assert_eq!(out.kind, Some(FormKind::Login));
    assert_eq!(
        roles(&out),
        vec![(0, Some("username")), (1, Some("password"))]
    );
}

#[test]
fn password_known_only_by_name_or_by_css_masking() {
    let out = Page::new("https://bank.example.com/login", "Internet banking")
        .form("User ID Password Login")
        .field(true, |f| {
            f.name = "loginName".into();
            f.labels = vec!["User ID".into()];
        })
        .field(true, |f| {
            f.name = "password".into();
            f.html_id = "password".into();
            f.labels = vec!["Password".into()];
            f.autocomplete = "off".into();
        })
        .run();
    assert_eq!(
        roles(&out),
        vec![(0, Some("username")), (1, Some("password"))]
    );

    let masked = Page::new("https://kiosk.example.com/login", "Kiosk")
        .form("Login")
        .field(true, |f| f.name = "txtUser".into())
        .field(true, |f| {
            f.name = "txtSecret".into();
            f.flags.masked = true;
        })
        .run();
    assert_eq!(masked.kind, Some(FormKind::Login));
    assert_eq!(
        roles(&masked),
        vec![(0, Some("username")), (1, Some("password"))]
    );
    assert!(
        masked.fields[1]
            .trace
            .iter()
            .any(|c| c.rule == "gate:text-security")
    );
}

#[test]
fn bank_card_number_before_a_password_is_the_username() {
    let out = Page::new("https://www.bank.example/ebm/signon", "Sign on")
        .form("Card number Password Remember my card Sign on")
        .field(true, |f| {
            f.name = "Card".into();
            f.labels = vec!["Card number".into()];
            f.max_length = Some(19);
        })
        .field(true, |f| {
            f.element = Element::Password;
            f.labels = vec!["Password".into()];
        })
        .run();
    assert_eq!(out.kind, Some(FormKind::Login));
    assert_eq!(
        roles(&out),
        vec![(0, Some("username")), (1, Some("password"))]
    );
    assert!(
        out.fields[0]
            .trace
            .iter()
            .any(|c| c.rule == "context:login-partner")
    );
}

#[test]
fn pinterest_style_signup() {
    let out = Page::new("https://www.example.com/", "Example")
        .heading("Welcome to Example")
        .field(false, |f| {
            f.element = Element::Email;
            f.name = "id".into();
            f.placeholder = "Email".into();
            f.autocomplete = "email".into();
        })
        .field(false, |f| {
            f.element = Element::Password;
            f.name = "password".into();
            f.placeholder = "Create a password".into();
            f.autocomplete = "new-password".into();
        })
        .field(false, |f| {
            f.element = Element::Other;
            f.name = "birthdate".into();
        })
        .button(false, "Continue")
        .button(false, "Already a member? Log in")
        .run();
    assert_eq!(out.kind, Some(FormKind::Signup));
    assert_eq!(
        roles(&out),
        vec![(0, Some("email")), (1, Some("new-password"))]
    );
}

#[test]
fn email_lookup_that_joins_or_signs_in() {
    let out = Page::new("https://accounts.example.com/lookup", "Example")
        .heading("Enter your email to join us or sign in.")
        .form("Country United States Change Email By continuing, I agree to the Privacy Policy and Terms of Use. Continue")
        .field(true, |f| {
            f.element = Element::Email;
            f.name = "username".into();
            f.labels = vec!["Email*".into()];
            f.autocomplete = "email".into();
        })
        .button(true, "Continue")
        .run();
    assert_eq!(out.kind, Some(FormKind::Login));
    assert_eq!(roles(&out), vec![(0, Some("email"))]);
}

#[test]
fn login_url_alone_does_not_make_a_newsletter_box_a_sign_in() {
    let out = Page::new("https://www.example.com/login/old-page", "Page not found")
        .heading("We couldn't find that page")
        .form("Get 10% off your first order Sign up")
        .field(true, |f| {
            f.element = Element::Email;
            f.placeholder = "Email address".into();
        })
        .button(true, "Sign up")
        .run();
    assert_eq!(out.kind, None);
    assert!(
        out.groups[0]
            .trace
            .iter()
            .any(|c| c.rule == "shape:identifier-only-url-against-wording")
    );
}
