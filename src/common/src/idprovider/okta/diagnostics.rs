//! Log only locally defined categories. IDX labels, messages and form values
//! are untrusted and may contain credentials or identifying information.
use super::{AuthRequest, AuthResult, IdpError};

pub(super) fn step(name: &str) -> &'static str {
    match name {
        "identify" => "identify",
        "challenge-authenticator" => "challenge-authenticator",
        "select-authenticator-authenticate" => "select-authenticator-authenticate",
        "select-authenticator-enroll" => "select-authenticator-enroll",
        "enroll-authenticator" => "enroll-authenticator",
        "reenroll-authenticator" => "reenroll-authenticator",
        "challenge-poll" => "challenge-poll",
        "enroll-poll" => "enroll-poll",
        "currentAuthenticator-send" => "currentAuthenticator-send",
        "currentAuthenticatorEnrollment-recover" => "currentAuthenticatorEnrollment-recover",
        "cancel" => "cancel",
        "skip" => "skip",
        _ => "unknown",
    }
}

pub(super) fn prompt(request: &AuthRequest) {
    let kind = match request {
        AuthRequest::Password { .. } => "password",
        AuthRequest::Input { .. } => "input",
        AuthRequest::Pin => "pin",
        AuthRequest::SetupPin { .. } => "setup_pin",
        AuthRequest::HelloTOTP { .. } => "local_totp",
        AuthRequest::WebAuthn { .. } => "webauthn",
        AuthRequest::Fido { .. } => "fido",
        AuthRequest::ChangePassword { .. } => "change_password",
        AuthRequest::MFAPoll { .. } => "poll",
        AuthRequest::MFAPollWait => {
            trace!(prompt = "poll_wait", "Okta authenticator approval pending");
            return;
        }
        AuthRequest::InitDenied { .. } => {
            debug!(
                outcome = "denied",
                "Okta authentication initialization denied"
            );
            return;
        }
    };
    debug!(prompt = kind, "Okta authentication input requested");
}

pub(super) fn result(result: &AuthResult) {
    match result {
        AuthResult::Success { .. } => debug!(outcome = "success", "Okta authentication succeeded"),
        AuthResult::Denied(_) => debug!(outcome = "denied", "Okta authentication denied"),
        AuthResult::Next(request) => prompt(request),
    }
}

pub(super) fn local_error(operation: &'static str, error: &IdpError) {
    // Never format IdpError: NotFound carries arbitrary strings.
    match error {
        IdpError::Tpm => error!(
            operation,
            reason = "tpm",
            "Okta local credential operation failed"
        ),
        IdpError::KeyStore => error!(
            operation,
            reason = "keystore",
            "Okta local credential operation failed"
        ),
        IdpError::BadRequest => debug!(
            operation,
            reason = "bad_request",
            "Okta authentication operation failed"
        ),
        IdpError::Transport => debug!(
            operation,
            reason = "transport",
            "Okta authentication operation unavailable"
        ),
        IdpError::ProviderUnauthorised => debug!(
            operation,
            reason = "refresh_rejected",
            "Okta reauthentication required"
        ),
        IdpError::NotFound { .. } => debug!(
            operation,
            reason = "not_found",
            "Okta cached credential unavailable"
        ),
    }
}

pub(super) fn local_failure(operation: &'static str, error: IdpError) -> IdpError {
    local_error(operation, &error);
    error
}

pub(super) fn invalid(reason: &'static str) -> IdpError {
    error!(
        reason,
        "Okta authentication state or identity validation failed"
    );
    IdpError::BadRequest
}

pub(super) fn expired() -> IdpError {
    warn!(
        reason = "session_expired",
        "Okta authentication session expired; restart sign-in"
    );
    IdpError::BadRequest
}

pub(super) fn interrupted() -> IdpError {
    debug!(
        reason = "shutdown",
        "Okta authentication interrupted by shutdown"
    );
    IdpError::BadRequest
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(super) mod testing {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::{span, Dispatch, Event, Subscriber};
    use tracing_subscriber::{layer::Context, prelude::*, Layer};

    #[derive(Clone, Default)]
    pub(crate) struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

    #[derive(Default)]
    struct Fields(BTreeMap<String, String>);

    impl Visit for Fields {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().into(), format!("{value:?}"));
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().into(), value.into());
        }
    }

    impl<S: Subscriber> Layer<S> for Capture {
        fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
            let mut fields = Fields::default();
            event.record(&mut fields);
            fields
                .0
                .insert("level".into(), event.metadata().level().to_string());
            self.0.lock().unwrap().push(fields.0);
        }
        fn on_new_span(&self, attrs: &span::Attributes<'_>, _: &span::Id, _: Context<'_, S>) {
            let mut fields = Fields::default();
            attrs.record(&mut fields);
            fields
                .0
                .insert("span".into(), attrs.metadata().name().into());
            self.0.lock().unwrap().push(fields.0);
        }
    }

    impl Capture {
        pub(crate) fn subscriber(&self) -> Dispatch {
            // Capture only our application events: dependencies have their own
            // diagnostics, and transport filtering is tested in the daemon.
            Dispatch::new(
                tracing_subscriber::registry().with(self.clone().with_filter(
                    tracing_subscriber::filter::filter_fn(|meta| {
                        meta.target().starts_with("himmelblau_unix_common")
                    }),
                )),
            )
        }
        pub(crate) fn contains(&self, field: &str, value: &str) -> bool {
            self.0
                .lock()
                .unwrap()
                .iter()
                .any(|event| event.get(field).is_some_and(|v| v == value))
        }
        pub(crate) fn output(&self) -> String {
            format!("{:?}", self.0.lock().unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::Capture;

    #[test]
    fn prompt_and_denial_messages_never_expose_payloads() {
        let logs = Capture::default();
        tracing::dispatcher::with_default(&logs.subscriber(), || {
            prompt(&AuthRequest::Input {
                enrollment: None,
                msg: "SECRET-PROMPT".into(),
                echo_on: false,
            });
            result(&AuthResult::Denied("SECRET-DENIAL".into()));
            local_error(
                "lookup",
                &IdpError::NotFound {
                    what: "SECRET-ACCOUNT".into(),
                    where_: "SECRET-URL".into(),
                },
            );
        });
        assert!(logs.contains("prompt", "input"));
        assert!(logs.contains("outcome", "denied"));
        assert!(!logs.contains("outcome", "success"));
        assert!(!logs.output().contains("SECRET-"));
    }

    #[test]
    fn pending_poll_is_trace_only() {
        let logs = Capture::default();
        tracing::dispatcher::with_default(&logs.subscriber(), || prompt(&AuthRequest::MFAPollWait));
        assert!(logs.contains("prompt", "poll_wait"));
        assert!(logs.contains("level", "TRACE"));
        assert!(!logs.contains("level", "DEBUG"));
    }
}
