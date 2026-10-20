//! Transport frame and connection diagnostics obscure authentication decisions.
//! Keep this independent of EnvFilter so verbose settings cannot restore them.
use tracing::{Level, Metadata};

pub(super) fn auth_log_enabled(metadata: &Metadata<'_>) -> bool {
    let target = metadata.target().split("::").next().unwrap_or("");
    !matches!(target, "hyper" | "hyper_util" | "h2" | "reqwest" | "rustls")
        || *metadata.level() <= Level::INFO
}

#[cfg(test)]
mod tests {
    use super::*;
    use sketching::tracing_subscriber::{filter::filter_fn, prelude::*, EnvFilter};

    #[test]
    fn explicit_trace_cannot_enable_transport_events_or_spans() {
        let subscriber = sketching::tracing_subscriber::registry()
            .with(filter_fn(auth_log_enabled))
            .with(EnvFilter::new(
                "trace,h2=trace,hyper::proto=trace,hyper_util=trace,reqwest=trace,rustls=trace",
            ));
        tracing::subscriber::with_default(subscriber, || {
            assert!(!tracing::event_enabled!(target: "h2::codec", Level::TRACE));
            assert!(!tracing::event_enabled!(target: "hyper::proto", Level::DEBUG));
            assert!(!tracing::event_enabled!(target: "hyper_util::client", Level::DEBUG));
            assert!(!tracing::event_enabled!(target: "reqwest::connect", Level::DEBUG));
            assert!(!tracing::event_enabled!(target: "rustls", Level::DEBUG));
            assert!(tracing::debug_span!(target: "h2", "Connection").is_disabled());
            assert!(tracing::trace_span!(target: "hyper::proto", "request").is_disabled());
            assert!(tracing::event_enabled!(target: "h2", Level::WARN));
            assert!(tracing::event_enabled!(target: "hyper::proto", Level::ERROR));
            assert!(
                tracing::event_enabled!(target: "himmelblau_unix_common::idprovider::okta", Level::DEBUG)
            );
            assert!(!tracing::debug_span!(target: "himmelblau_unix_common::idprovider::okta", "authentication").is_disabled());
            assert!(tracing::event_enabled!(target: "hyper_application", Level::DEBUG));
        });
    }

    #[test]
    fn normal_info_filter_still_applies_to_application_events() {
        let subscriber = sketching::tracing_subscriber::registry()
            .with(filter_fn(auth_log_enabled))
            .with(EnvFilter::new("info"));
        tracing::subscriber::with_default(subscriber, || {
            assert!(
                !tracing::event_enabled!(target: "himmelblau_unix_common::idprovider::okta", Level::DEBUG)
            );
            assert!(
                tracing::event_enabled!(target: "himmelblau_unix_common::idprovider::okta", Level::INFO)
            );
            assert!(!tracing::event_enabled!(target: "h2", Level::DEBUG));
            assert!(tracing::event_enabled!(target: "h2", Level::WARN));
        });
    }
}
