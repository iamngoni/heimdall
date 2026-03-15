//
//  heimdall
//  src/util.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/15.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

/// Saturating cast from u64 to i32. Clamps to i32::MAX on overflow.
#[inline]
pub fn sat_i32(value: u64) -> i32 {
    value.min(i32::MAX as u64) as i32
}

/// Saturating cast from u128 to i32. Clamps to i32::MAX on overflow.
#[inline]
pub fn sat_i32_u128(value: u128) -> i32 {
    value.min(i32::MAX as u128) as i32
}

/// Saturating cast from i64 to i32. Clamps to i32::MIN..i32::MAX.
#[inline]
pub fn sat_i32_i64(value: i64) -> i32 {
    value.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// Saturating cast from usize to i32. Clamps to i32::MAX on overflow.
#[inline]
pub fn sat_i32_usize(value: usize) -> i32 {
    value.min(i32::MAX as usize) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sat_i32_within_range() {
        assert_eq!(sat_i32(42), 42);
        assert_eq!(sat_i32(0), 0);
    }

    #[test]
    fn sat_i32_overflow_clamps() {
        assert_eq!(sat_i32(u64::MAX), i32::MAX);
        assert_eq!(sat_i32(3_000_000_000), i32::MAX);
    }

    #[test]
    fn sat_i32_u128_overflow_clamps() {
        assert_eq!(sat_i32_u128(u128::MAX), i32::MAX);
        assert_eq!(sat_i32_u128(500), 500);
    }

    #[test]
    fn sat_i32_i64_clamps_both_ends() {
        assert_eq!(sat_i32_i64(i64::MAX), i32::MAX);
        assert_eq!(sat_i32_i64(i64::MIN), i32::MIN);
        assert_eq!(sat_i32_i64(100), 100);
    }

    #[test]
    fn sat_i32_usize_overflow_clamps() {
        assert_eq!(sat_i32_usize(usize::MAX), i32::MAX);
        assert_eq!(sat_i32_usize(42), 42);
    }
}
