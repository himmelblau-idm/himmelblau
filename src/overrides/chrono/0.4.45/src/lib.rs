//! The UTC subset of chrono used by this workspace's dependencies, backed by jiff.

use std::{fmt, marker::PhantomData};

pub mod prelude {
    pub use crate::DateTime;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Utc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DateTime<Tz> {
    timestamp: jiff::Timestamp,
    timezone: PhantomData<Tz>,
}

impl Utc {
    pub fn now() -> DateTime<Utc> {
        DateTime {
            timestamp: jiff::Timestamp::now(),
            timezone: PhantomData,
        }
    }
}

pub trait TimeZone {
    fn timestamp_opt(&self, seconds: i64, nanos: u32) -> LocalResult<DateTime<Self>>
    where
        Self: Sized;
}

pub struct LocalResult<T>(Option<T>);

impl<T> LocalResult<T> {
    pub fn single(self) -> Option<T> {
        self.0
    }
}

impl TimeZone for Utc {
    fn timestamp_opt(&self, seconds: i64, nanos: u32) -> LocalResult<DateTime<Self>> {
        let timestamp = if nanos < 1_000_000_000 {
            jiff::Timestamp::new(seconds, nanos as i32).ok()
        } else {
            None
        };
        LocalResult(timestamp.map(|timestamp| DateTime {
            timestamp,
            timezone: PhantomData,
        }))
    }
}

pub struct Duration(jiff::SignedDuration);

impl Duration {
    pub fn from_std(duration: std::time::Duration) -> Result<Self, jiff::Error> {
        jiff::SignedDuration::try_from(duration).map(Self)
    }
}

impl DateTime<Utc> {
    pub fn timestamp(&self) -> i64 {
        // jiff's as_second truncates toward zero; chrono rounds down.
        self.timestamp.as_nanosecond().div_euclid(1_000_000_000) as i64
    }

    pub fn checked_add_signed(self, duration: Duration) -> Option<Self> {
        self.timestamp
            .checked_add(duration.0)
            .ok()
            .map(|timestamp| Self {
                timestamp,
                timezone: PhantomData,
            })
    }

    pub fn format<'a>(&self, format: &'a str) -> jiff::fmt::strtime::Display<'a> {
        self.timestamp.strftime(format)
    }
}

impl From<std::time::SystemTime> for DateTime<Utc> {
    fn from(time: std::time::SystemTime) -> Self {
        Self {
            timestamp: jiff::Timestamp::try_from(time).expect("SystemTime out of range"),
            timezone: PhantomData,
        }
    }
}

impl fmt::Display for DateTime<Utc> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let datetime = self.timestamp.to_zoned(jiff::tz::TimeZone::UTC).datetime();
        write!(f, "{} {} UTC", datetime.date(), datetime.time())
    }
}

#[cfg(feature = "serde")]
pub mod serde {
    pub mod ts_seconds_option {
        use crate::{DateTime, TimeZone, Utc};
        use ::serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(
            value: &Option<DateTime<Utc>>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            value
                .as_ref()
                .map(DateTime::timestamp)
                .serialize(serializer)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<DateTime<Utc>>, D::Error> {
            Option::<i64>::deserialize(deserializer)?
                .map(|seconds| {
                    Utc.timestamp_opt(seconds, 0)
                        .single()
                        .ok_or_else(|| ::serde::de::Error::custom("Unix timestamp out of range"))
                })
                .transpose()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_time_conversion_for_credential_display() {
        use crate::prelude::DateTime;
        use std::time::{Duration, UNIX_EPOCH};

        let epoch = DateTime::<Utc>::from(UNIX_EPOCH);
        assert_eq!(epoch, Utc.timestamp_opt(0, 0).single().unwrap());
        assert_eq!(epoch.to_string(), "1970-01-01 00:00:00 UTC");
        assert_eq!(
            DateTime::<Utc>::from(UNIX_EPOCH - Duration::from_millis(500)),
            Utc.timestamp_opt(-1, 500_000_000).single().unwrap()
        );
        assert_eq!(
            DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(u32::MAX.into())),
            Utc.timestamp_opt(u32::MAX.into(), 0).single().unwrap()
        );
    }

    #[test]
    fn unix_seconds_round_down_and_nanoseconds_are_validated() {
        let before_epoch = Utc.timestamp_opt(-1, 500_000_000).single().unwrap();
        let epoch = Utc.timestamp_opt(0, 0).single().unwrap();
        assert_eq!(before_epoch.timestamp(), -1);
        assert!(before_epoch < epoch);
        assert_eq!(
            Utc.timestamp_opt(1, 500_000_000)
                .single()
                .unwrap()
                .timestamp(),
            1
        );
        assert!(Utc.timestamp_opt(0, 1_000_000_000).single().is_none());
        assert!(Utc.timestamp_opt(i64::MAX, 0).single().is_none());
    }

    #[test]
    fn timeout_addition_preserves_fraction_and_checks_overflow() {
        let start = Utc.timestamp_opt(-1, 500_000_000).single().unwrap();
        let duration = Duration::from_std(std::time::Duration::from_millis(750)).unwrap();
        assert_eq!(
            start.checked_add_signed(duration),
            Utc.timestamp_opt(0, 250_000_000).single()
        );
        let max = DateTime::<Utc> {
            timestamp: jiff::Timestamp::MAX,
            timezone: PhantomData,
        };
        assert!(max
            .checked_add_signed(Duration::from_std(std::time::Duration::from_nanos(1)).unwrap())
            .is_none());
        assert!(Duration::from_std(std::time::Duration::MAX).is_err());
    }

    #[test]
    fn intune_status_format_is_utc_without_fractional_seconds() {
        let date = Utc.timestamp_opt(0, 123_000_000).single().unwrap();
        assert_eq!(
            date.format("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
            "1970-01-01T00:00:00+00:00"
        );
        assert_eq!(date.to_string(), "1970-01-01 00:00:00.123 UTC");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn optional_unix_seconds_json() {
        #[derive(::serde::Serialize, ::serde::Deserialize)]
        struct Claims {
            #[serde(with = "crate::serde::ts_seconds_option")]
            exp: Option<DateTime<Utc>>,
        }

        for seconds in [-1, 0, 1234567890] {
            let json = format!("{{\"exp\":{seconds}}}");
            let claims: Claims = serde_json::from_str(&json).unwrap();
            assert_eq!(claims.exp.unwrap().timestamp(), seconds);
            assert_eq!(serde_json::to_string(&claims).unwrap(), json);
        }
        let claims = Claims {
            exp: Utc.timestamp_opt(-1, 500_000_000).single(),
        };
        assert_eq!(serde_json::to_string(&claims).unwrap(), r#"{"exp":-1}"#);
        let claims: Claims = serde_json::from_str(r#"{"exp":null}"#).unwrap();
        assert!(claims.exp.is_none());
        assert_eq!(serde_json::to_string(&claims).unwrap(), r#"{"exp":null}"#);
        for invalid in [
            r#"{"exp":1.5}"#,
            r#"{"exp":"1"}"#,
            r#"{"exp":9223372036854775807}"#,
        ] {
            assert!(serde_json::from_str::<Claims>(invalid).is_err());
        }
    }
}
