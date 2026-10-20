//! Adapter for the public contract in docs/okta-auth-rs-handoff.md.
use okta::{FailureKind, FailureStage, OktaError};
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum FailureAction {
    Retry(Duration),
    RejectRefresh,
    Reject,
}

pub(super) fn classify(error: &OktaError) -> FailureAction {
    match error {
        OktaError::OperationFailed(failure) => {
            if matches!(
                failure.kind,
                FailureKind::Trust | FailureKind::TokenValidation
            ) {
                return FailureAction::Reject;
            }
            if matches!(failure.kind, FailureKind::Transport)
                || matches!(failure.http_status, Some(408 | 429 | 500 | 502 | 503 | 504))
            {
                return FailureAction::Retry(
                    failure
                        .retry_after
                        .unwrap_or(Duration::from_secs(15))
                        .clamp(Duration::from_secs(1), Duration::from_secs(3600)),
                );
            }
            if failure.stage == FailureStage::Refresh
                && failure.oauth_error.as_deref() == Some("invalid_grant")
            {
                return FailureAction::RejectRefresh;
            }
            FailureAction::Reject
        }
        _ => FailureAction::Reject,
    }
}

// Codes are diagnostic categories, never arbitrary strings from the server.
fn oauth_code(code: Option<&str>) -> &'static str {
    match code {
        None => "none",
        Some("invalid_grant") => "invalid_grant",
        Some("invalid_client") => "invalid_client",
        Some("unauthorized_client") => "unauthorized_client",
        Some("access_denied") => "access_denied",
        Some("invalid_request") => "invalid_request",
        Some("invalid_scope") => "invalid_scope",
        Some("unsupported_grant_type") => "unsupported_grant_type",
        Some("interaction_required") => "interaction_required",
        Some("login_required") => "login_required",
        Some("temporarily_unavailable") => "temporarily_unavailable",
        Some("server_error") => "server_error",
        _ => "unknown",
    }
}

pub(super) fn log_failure(operation: &'static str, error: &OktaError) {
    report_failure(operation, error, false);
}

pub(super) fn log_reconciliation(error: &OktaError) {
    report_failure("uncertain_submission", error, true);
}

fn report_failure(operation: &'static str, error: &OktaError, reconciling: bool) {
    if let OktaError::OperationFailed(failure) = error {
        let action = classify(error);
        let (recovery, retry_seconds) = if reconciling {
            ("introspect_once", None)
        } else {
            match action {
                FailureAction::Retry(delay) => ("retry_later", Some(delay.as_secs())),
                FailureAction::RejectRefresh => ("reauthenticate", None),
                FailureAction::Reject => ("reject", None),
            }
        };
        macro_rules! report {
            ($level:expr) => {
                event!($level, operation, stage = ?failure.stage, kind = ?failure.kind,
                    http_status = failure.http_status, request_outcome = ?failure.outcome,
                    oauth_code = oauth_code(failure.oauth_error.as_deref()),
                    okta_error_code_present = failure.okta_error_code.is_some(),
                    recovery, retry_seconds, "Okta authentication operation failed")
            };
        }
        match action {
            FailureAction::Retry(_) => report!(tracing::Level::INFO),
            _ if matches!(
                failure.kind,
                FailureKind::Trust | FailureKind::TokenValidation | FailureKind::Protocol
            ) =>
            {
                report!(tracing::Level::ERROR)
            }
            _ => report!(tracing::Level::DEBUG),
        }
    } else {
        let reason = match error {
            OktaError::Configuration => "configuration",
            OktaError::StaleStep => "stale_step",
            OktaError::WrongClient => "wrong_client",
            OktaError::Uncertain => "uncertain",
            OktaError::Canceled => "canceled",
            OktaError::ReservedInput => "reserved_input",
            OktaError::UnsupportedResult => "unsupported_result",
            OktaError::InvalidContinuation => "invalid_continuation",
            OktaError::OperationFailed(_) => "operation_failed",
        };
        if matches!(
            error,
            OktaError::Configuration | OktaError::WrongClient | OktaError::InvalidContinuation
        ) {
            error!(operation, reason, "Okta authentication operation rejected");
        } else {
            debug!(operation, reason, "Okta authentication operation rejected");
        }
    }
}

/// Only a capability probe may downgrade. Actual logins never call this.
pub(super) fn permits_probe_fallback(error: &OktaError) -> bool {
    match error {
        OktaError::OperationFailed(failure) => {
            !matches!(
                failure.kind,
                FailureKind::Trust | FailureKind::TokenValidation
            ) && matches!(
                failure.stage,
                FailureStage::Interact | FailureStage::Introspect
            ) && !matches!(classify(error), FailureAction::Retry(_))
        }
        OktaError::Configuration | OktaError::UnsupportedResult => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use okta::{OperationFailure, RequestOutcome};

    fn http(stage: FailureStage, status: u16, code: Option<&str>) -> OktaError {
        OktaError::OperationFailed(OperationFailure {
            kind: FailureKind::Http,
            stage,
            http_status: Some(status),
            oauth_error: code.map(str::to_owned),
            okta_error_code: None,
            retry_after: None,
            outcome: RequestOutcome::ResponseReceived,
        })
    }

    #[test]
    fn failure_details_exclude_arbitrary_protocol_codes() {
        let logs = super::super::diagnostics::testing::Capture::default();
        let mut error = http(FailureStage::Remediation, 400, Some("SECRET-OAUTH"));
        if let OktaError::OperationFailed(failure) = &mut error {
            failure.okta_error_code = Some("SECRET-OKTA".into());
        }
        tracing::dispatcher::with_default(&logs.subscriber(), || {
            log_failure("remediation", &error)
        });
        assert!(logs.contains("stage", "Remediation"));
        assert!(logs.contains("http_status", "400"));
        assert!(logs.contains("oauth_code", "unknown"));
        assert!(logs.contains("recovery", "reject"));
        assert!(!logs.output().contains("SECRET-"));
    }

    #[test]
    fn refresh_rejection_logs_reauthentication() {
        let logs = super::super::diagnostics::testing::Capture::default();
        tracing::dispatcher::with_default(&logs.subscriber(), || {
            log_failure(
                "refresh",
                &http(FailureStage::Refresh, 400, Some("invalid_grant")),
            );
        });
        assert!(logs.contains("oauth_code", "invalid_grant"));
        assert!(logs.contains("recovery", "reauthenticate"));
        assert!(!logs.contains("recovery", "retry_later"));
    }

    #[test]
    fn outage_logs_effective_retry_delay() {
        let logs = super::super::diagnostics::testing::Capture::default();
        let mut error = http(FailureStage::Remediation, 429, None);
        if let OktaError::OperationFailed(failure) = &mut error {
            failure.retry_after = Some(Duration::from_secs(7200));
        }
        tracing::dispatcher::with_default(&logs.subscriber(), || {
            log_failure("remediation", &error)
        });
        assert!(logs.contains("level", "INFO"));
        assert!(logs.contains("retry_seconds", "3600"));
        assert!(logs.contains("recovery", "retry_later"));
    }

    #[test]
    fn only_native_endpoint_absence_selects_fallback() {
        assert!(permits_probe_fallback(&http(
            FailureStage::Interact,
            404,
            None
        )));
        assert!(!permits_probe_fallback(&http(
            FailureStage::Discovery,
            404,
            None
        )));
        assert!(!permits_probe_fallback(&http(
            FailureStage::Interact,
            503,
            None
        )));
        assert!(!permits_probe_fallback(&http(
            FailureStage::Interact,
            429,
            None
        )));
        assert!(permits_probe_fallback(&http(
            FailureStage::Interact,
            501,
            None
        )));
    }

    #[test]
    fn refresh_rejection_is_not_an_outage() {
        assert_eq!(
            classify(&http(FailureStage::Refresh, 400, Some("invalid_grant"))),
            FailureAction::RejectRefresh
        );
        assert_eq!(
            classify(&http(FailureStage::Remediation, 400, Some("invalid_grant"))),
            FailureAction::Reject
        );
    }
}
