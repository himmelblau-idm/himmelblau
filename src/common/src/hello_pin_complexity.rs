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
use crate::constants::DEFAULT_HELLO_PIN_MIN_LEN;

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
    fn test_complex_pins() {
        assert!(!is_simple_pin("123451")); // delta (1,1,1,1,6)
        assert!(!is_simple_pin("187265")); // delta (7,9,5,4,9)
        assert!(!is_simple_pin("abcxyz")); // non-digit
        assert!(!is_simple_pin("12a456")); // mixed input
        assert!(!is_simple_pin("432187")); // delta (9,9,9,7,9)
    }
}
