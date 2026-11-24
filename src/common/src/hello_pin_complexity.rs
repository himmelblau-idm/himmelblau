/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2025

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
use crate::{
    constants::{DEFAULT_HELLO_PIN_MIN_LEN, POLICY_CACHE},
    policy_cache::{PolicyCache, PolicyValue},
};

/// Composition of an enrolled Hello PIN (stored for compliance reporting; never the PIN itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinComposition {
    pub length: u32,
    pub digits: u32,
    pub lowercase: u32,
    pub uppercase: u32,
    pub symbols: u32,
}

const ENROLLED_PIN_COMPOSITION_KEY: &str = "hello_pin_enrolled_composition";

pub fn pin_composition(pin: &str) -> PinComposition {
    PinComposition {
        length: pin.chars().count() as u32,
        digits: pin.chars().filter(|c| c.is_ascii_digit()).count() as u32,
        lowercase: pin.chars().filter(|c| c.is_ascii_lowercase()).count() as u32,
        uppercase: pin.chars().filter(|c| c.is_ascii_uppercase()).count() as u32,
        symbols: pin.chars().filter(|c| !(c.is_ascii_alphanumeric())).count() as u32,
    }
}

fn composition_to_policy_value(comp: PinComposition) -> PolicyValue {
    PolicyValue::Text(format!(
        "{}:{}:{}:{}:{}",
        comp.length, comp.digits, comp.lowercase, comp.uppercase, comp.symbols
    ))
}

fn parse_enrolled_composition(value: &PolicyValue) -> Option<PinComposition> {
    let PolicyValue::Text(raw) = value else {
        return None;
    };
    let mut parts = raw.split(':');
    let length = parts.next()?.parse().ok()?;
    let digits = parts.next()?.parse().ok()?;
    let lowercase = parts.next()?.parse().ok()?;
    let uppercase = parts.next()?.parse().ok()?;
    let symbols = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(PinComposition {
        length,
        digits,
        lowercase,
        uppercase,
        symbols,
    })
}

/// Persist the last known Hello PIN composition (requires root).
pub fn record_enrolled_pin_composition(pin: &str) -> Result<(), String> {
    let policy_cache = PolicyCache::new(POLICY_CACHE, true)
        .map_err(|_| "Failed to open policy cache.".to_string())?;
    let comp = pin_composition(pin);
    policy_cache
        .set(
            ENROLLED_PIN_COMPOSITION_KEY,
            &composition_to_policy_value(comp),
        )
        .map_err(|_| "Failed to store enrolled Hello PIN composition.".to_string())
}

/// Last recorded Hello PIN composition, if any (for compliance checks).
pub fn enrolled_pin_composition() -> Result<Option<PinComposition>, String> {
    let policy_cache = PolicyCache::new(POLICY_CACHE, false)
        .map_err(|_| "Failed to load policy cache.".to_string())?;
    Ok(policy_cache
        .get(ENROLLED_PIN_COMPOSITION_KEY)
        .as_ref()
        .and_then(parse_enrolled_composition))
}

/// Returns true if the provided PIN is too simple (constant delta pattern)
/// and should be disallowed, per Hello PIN rules.
/// Only numeric PINs are supported (non-digit PINs will return false).
pub fn is_simple_pin(pin: &str) -> bool {
    // Short pins are considered "simple"
    if pin.len() < DEFAULT_HELLO_PIN_MIN_LEN {
        return true;
    }

    // Non-numeric pins are not considered "simple". Convert to digits and
    // return false if any character isn't a digit
    let digits: Vec<u8> = match pin
        .chars()
        .map(|c| c.to_digit(10).map(|d| d as u8))
        .collect::<Option<Vec<u8>>>()
    {
        Some(d) => d,
        None => return false,
    };

    let deltas: Vec<u8> = digits
        .windows(2)
        .map(|pair| (10 + pair[1] - pair[0]) % 10)
        .collect();

    // Check if all deltas are equal
    deltas.windows(2).all(|w| w[0] == w[1])
}

pub fn meets_intune_pin_policy(pin: &str) -> Result<(), String> {
    let policy_cache = PolicyCache::new(POLICY_CACHE, false)
        .map_err(|_| "Failed to load policy cache.".to_string())?;

    let PinComposition {
        length,
        digits: count_digits,
        lowercase: count_lower,
        uppercase: count_upper,
        symbols: count_symbols,
    } = pin_composition(pin);

    macro_rules! check_policy {
        ($key:expr, $actual:expr, $label:expr) => {
            if let Some(PolicyValue::Int(min)) = policy_cache.get($key) {
                if $actual < min {
                    return Err(format!(
                        "PIN is not compliant with administrator policy: must contain at least {} {} character{}.",
                        min, $label, if min == 1 { "" } else { "s" }
                    ));
                }
            }
        };
    }

    check_policy!("linux_passwordpolicy_minimumlength", length, "total");
    check_policy!("linux_passwordpolicy_minimumdigits", count_digits, "digit");
    check_policy!(
        "linux_passwordpolicy_minimumlowercase",
        count_lower,
        "lowercase"
    );
    check_policy!(
        "linux_passwordpolicy_minimumuppercase",
        count_upper,
        "uppercase"
    );
    check_policy!(
        "linux_passwordpolicy_minimumsymbols",
        count_symbols,
        "symbol"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_pins() {
        assert!(is_simple_pin("111111")); // delta 0
        assert!(is_simple_pin("123456")); // delta 1
        assert!(is_simple_pin("135791")); // delta 2
        assert!(is_simple_pin("963074")); // delta 7
        assert!(is_simple_pin("159371")); // delta 4
        assert!(is_simple_pin("703692")); // delta 3
        assert!(is_simple_pin("")); // too short
        assert!(is_simple_pin("1")); // too short
        assert!(is_simple_pin("abcx")); // too short
    }

    #[test]
    fn pin_composition_counts_mixed_pin() {
        let comp = pin_composition("Ab1!2345");
        assert_eq!(comp.length, 8);
        assert_eq!(comp.digits, 5);
        assert_eq!(comp.lowercase, 1);
        assert_eq!(comp.uppercase, 1);
        assert_eq!(comp.symbols, 1);
    }

    #[test]
    fn test_complex_pins() {
        assert!(!is_simple_pin("123451")); // delta (1,1,1,1,6)
        assert!(!is_simple_pin("187265")); // delta (7,9,5,4,9)
        assert!(!is_simple_pin("abcxyz")); // non-digit
        assert!(!is_simple_pin("12a456")); // mixed input
        assert!(!is_simple_pin("432187")); // delta (9,9,9,7,9)
    }
}
