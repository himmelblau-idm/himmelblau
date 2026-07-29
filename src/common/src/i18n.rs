use gettextrs::{
    bind_textdomain_codeset, bindtextdomain, gettext, ngettext, setlocale, textdomain,
    LocaleCategory,
};
use lazy_static::lazy_static;
use regex::Regex;
use std::env;
use std::path::PathBuf;
use std::sync::Once;

pub const DOMAIN: &str = "himmelblau";
const SYSTEM_LOCALEDIR: &str = "/usr/share/locale";
const LOCALEDIR_ENV: &str = "HIMMELBLAU_LOCALEDIR";

static INIT: Once = Once::new();

lazy_static! {
    static ref AUTHENTICATOR_ENTROPY_RE: Option<Regex> =
        Regex::new(r"^Open your Authenticator app, and enter the number '([^']+)' to sign in\.$")
            .ok();
    static ref TEXTED_PHONE_RE: Option<Regex> =
        Regex::new(r"^We texted your phone (.+)\. Please enter the code to sign in:$").ok();
    static ref CALLING_PHONE_RE: Option<Regex> =
        Regex::new(r"^We're calling your phone (.+)\. Please answer it to continue\.$").ok();
    static ref CALLING_OFFICE_RE: Option<Regex> =
        Regex::new(r"^We're calling your office phone (.+)\. Please answer it to continue\.$").ok();
    static ref DAG_FALLBACK_RE: Option<Regex> = Regex::new(
        r"(?s)^Using a browser on another device, visit:\n(.+)\n\s*And enter the code:\n(.+)$"
    )
    .ok();
}

fn locale_dir() -> PathBuf {
    env::var_os(LOCALEDIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(SYSTEM_LOCALEDIR))
}

pub fn init() {
    INIT.call_once(|| {
        let _ = setlocale(LocaleCategory::LcMessages, "");
        let _ = bindtextdomain(DOMAIN, locale_dir());
        let _ = bind_textdomain_codeset(DOMAIN, "UTF-8");
        let _ = textdomain(DOMAIN);
    });
}

pub fn tr(msgid: &str) -> String {
    init();
    gettext(msgid)
}

pub fn trn(singular: &str, plural: &str, n: u32) -> String {
    init();
    ngettext(singular, plural, n)
}

pub fn tr_fmt(msgid: &str, values: &[(&str, String)]) -> String {
    replace_placeholders(tr(msgid), values)
}

pub fn trn_fmt(singular: &str, plural: &str, n: u32, values: &[(&str, String)]) -> String {
    replace_placeholders(trn(singular, plural, n), values)
}

fn replace_placeholders(mut msg: String, values: &[(&str, String)]) -> String {
    for (key, value) in values {
        msg = msg.replace(&format!("{{{key}}}"), value);
    }
    msg
}

pub fn translate_external_message(msg: &str) -> String {
    if msg.trim().is_empty() {
        return msg.to_string();
    }

    if let Some(captures) = AUTHENTICATOR_ENTROPY_RE
        .as_ref()
        .and_then(|re| re.captures(msg))
    {
        return tr_fmt(
            "Open your Authenticator app, and enter the number '{entropy}' to sign in.",
            &[("entropy", captures[1].to_string())],
        );
    }

    if let Some(captures) = TEXTED_PHONE_RE.as_ref().and_then(|re| re.captures(msg)) {
        return tr_fmt(
            "We texted your phone {phone}. Please enter the code to sign in:",
            &[("phone", captures[1].to_string())],
        );
    }

    if let Some(captures) = CALLING_PHONE_RE.as_ref().and_then(|re| re.captures(msg)) {
        return tr_fmt(
            "We're calling your phone {phone}. Please answer it to continue.",
            &[("phone", captures[1].to_string())],
        );
    }

    if let Some(captures) = CALLING_OFFICE_RE.as_ref().and_then(|re| re.captures(msg)) {
        return tr_fmt(
            "We're calling your office phone {phone}. Please answer it to continue.",
            &[("phone", captures[1].to_string())],
        );
    }

    if let Some(captures) = DAG_FALLBACK_RE.as_ref().and_then(|re| re.captures(msg)) {
        return tr_fmt(
            "Using a browser on another device, visit:\n{verification_uri}\nAnd enter the code:\n{user_code}",
            &[
                ("verification_uri", captures[1].trim().to_string()),
                ("user_code", captures[2].trim().to_string()),
            ],
        );
    }

    tr(msg)
}

#[cfg(test)]
mod tests {
    use super::{replace_placeholders, translate_external_message};

    #[test]
    fn replaces_named_placeholders() {
        let msg = replace_placeholders(
            "You have {attempts} attempts left.".to_string(),
            &[("attempts", "3".to_string())],
        );
        assert_eq!(msg, "You have 3 attempts left.");
    }

    #[test]
    fn keeps_unknown_placeholders() {
        let msg = replace_placeholders(
            "Use {known} and {unknown}.".to_string(),
            &[("known", "this".to_string())],
        );
        assert_eq!(msg, "Use this and {unknown}.");
    }

    #[test]
    fn translates_dynamic_external_message_to_english_without_catalog() {
        let msg = translate_external_message(
            "Open your Authenticator app, and enter the number '42' to sign in.",
        );
        assert!(msg.contains("42"));
        assert!(!msg.contains("{entropy}"));
    }
}
