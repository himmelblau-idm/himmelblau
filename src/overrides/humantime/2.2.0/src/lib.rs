//! Only the duration interface required by console-subscriber.
//!
//! Parsing uses jiff's friendly unsigned-duration grammar.

use std::{str::FromStr, time::Duration as StdDuration};

pub struct Duration(StdDuration);

impl FromStr for Duration {
    type Err = jiff::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        jiff::fmt::friendly::SpanParser::new()
            .parse_unsigned_duration(value)
            .map(Self)
    }
}

impl From<Duration> for StdDuration {
    fn from(value: Duration) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_console_durations() {
        for (input, seconds) in [("1h", 3_600), ("1000ms", 1), ("1h 2min 3s", 3_723)] {
            let duration: StdDuration = input.parse::<Duration>().unwrap().into();
            assert_eq!(duration, StdDuration::from_secs(seconds));
        }
    }

    #[test]
    fn rejects_invalid_and_overflowing_durations() {
        for input in ["", "1fortnight", "18446744073709551615h"] {
            assert!(input.parse::<Duration>().is_err(), "{input}");
        }
    }
}
