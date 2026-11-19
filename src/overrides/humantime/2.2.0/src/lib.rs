//! Duration parsing compatibility for console-subscriber.

mod duration;

pub use duration::{parse_duration, Error};
use std::{str::FromStr, time::Duration as StdDuration};

#[derive(Debug)]
pub struct Duration(StdDuration);

impl FromStr for Duration {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_duration(value).map(Self)
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
        for (input, seconds) in [
            ("1h", 3_600),
            ("1000ms", 1),
            ("1h 2min 3s", 3_723),
            ("1M", 2_630_016),
            ("1y", 31_557_600),
        ] {
            let duration: StdDuration = input.parse::<Duration>().unwrap().into();
            assert_eq!(duration, StdDuration::from_secs(seconds));
        }
    }

    #[test]
    fn normalizes_nanoseconds_and_checks_second_carry() {
        assert_eq!(
            parse_duration("18446744073709551615s 999999999ns"),
            Ok(StdDuration::MAX)
        );
        assert_eq!(
            parse_duration("18446744073709551614s 500000000ns 500000000ns"),
            Ok(StdDuration::from_secs(u64::MAX))
        );
        for input in [
            "18446744073709551615s 1000000000ns",
            "18446744073709551615s 500000000ns 500000000ns",
            "1000000000ns 18446744073709551615s",
        ] {
            assert_eq!(parse_duration(input), Err(Error::NumberOverflow), "{input}");
        }
    }

    #[test]
    fn rejects_invalid_and_overflowing_durations() {
        for input in ["", "1fortnight", "18446744073709551615h"] {
            assert!(input.parse::<Duration>().is_err(), "{input}");
        }
    }
}
