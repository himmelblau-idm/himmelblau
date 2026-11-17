//! Minimal duration parsing compatibility for console-subscriber.

pub struct Duration(std::time::Duration);

impl std::str::FromStr for Duration {
    type Err = jiff::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        jiff::fmt::friendly::SpanParser::new()
            .parse_unsigned_duration(input)
            .map(Self)
    }
}

impl From<Duration> for std::time::Duration {
    fn from(duration: Duration) -> Self {
        duration.0
    }
}
