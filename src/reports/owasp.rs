//
//  heimdall
//  src/reports/owasp.rs
//
//  Created by Ngonidzashe Mangudya on 2026/05/04.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

//! Map a CWE identifier to its OWASP Top 10 (2021) category.
//!
//! The lookup table covers the CWEs Heimdall actually emits today plus the
//! canonical members of each OWASP category. Falls back to `None` for CWEs
//! outside the Top 10 — the report renders a `—` in that case.

#[derive(Debug, Clone, Copy)]
pub struct OwaspCategory {
    pub code: &'static str,
    pub title: &'static str,
}

const A01: OwaspCategory = OwaspCategory {
    code: "A01:2021",
    title: "Broken Access Control",
};
const A02: OwaspCategory = OwaspCategory {
    code: "A02:2021",
    title: "Cryptographic Failures",
};
const A03: OwaspCategory = OwaspCategory {
    code: "A03:2021",
    title: "Injection",
};
const A04: OwaspCategory = OwaspCategory {
    code: "A04:2021",
    title: "Insecure Design",
};
const A05: OwaspCategory = OwaspCategory {
    code: "A05:2021",
    title: "Security Misconfiguration",
};
const A06: OwaspCategory = OwaspCategory {
    code: "A06:2021",
    title: "Vulnerable and Outdated Components",
};
const A07: OwaspCategory = OwaspCategory {
    code: "A07:2021",
    title: "Identification and Authentication Failures",
};
const A08: OwaspCategory = OwaspCategory {
    code: "A08:2021",
    title: "Software and Data Integrity Failures",
};
const A09: OwaspCategory = OwaspCategory {
    code: "A09:2021",
    title: "Security Logging and Monitoring Failures",
};
const A10: OwaspCategory = OwaspCategory {
    code: "A10:2021",
    title: "Server-Side Request Forgery (SSRF)",
};

/// Look up the OWASP Top 10 (2021) category for a CWE id like "CWE-89".
/// Accepts both `CWE-89` and the bare number `89`. Case-insensitive.
pub fn lookup(cwe_id: &str) -> Option<OwaspCategory> {
    let normalized = cwe_id.trim().to_uppercase();
    let n = normalized.strip_prefix("CWE-").unwrap_or(&normalized);
    let n: u32 = n.parse().ok()?;
    map(n)
}

fn map(cwe: u32) -> Option<OwaspCategory> {
    Some(match cwe {
        // A01 — Broken Access Control
        22 | 23 | 35 | 59 | 200 | 201 | 219 | 264 | 275 | 276 | 284 | 285 | 352 | 359 | 377
        | 402 | 425 | 441 | 497 | 538 | 540 | 548 | 552 | 566 | 601 | 639 | 651 | 668 | 706
        | 862 | 863 | 913 | 922 | 1275 => A01,

        // A02 — Cryptographic Failures (incl. CWE-338, weak PRNG)
        261 | 296 | 310 | 319 | 321 | 322 | 323 | 324 | 325 | 326 | 327 | 328 | 329 | 330 | 331
        | 335 | 336 | 337 | 338 | 340 | 347 | 523 | 720 | 757 | 759 | 760 | 780 | 818 | 916 => A02,

        // A03 — Injection (incl. XSS, since OWASP folded it in for 2021)
        20 | 74 | 75 | 77 | 78 | 79 | 80 | 83 | 87 | 88 | 89 | 90 | 91 | 93 | 94 | 95 | 96 | 97
        | 98 | 99 | 100 | 113 | 116 | 138 | 184 | 470 | 471 | 564 | 610 | 643 | 644 | 652 | 917
        | 1321 => A03,

        // A04 — Insecure Design
        73 | 183 | 209 | 213 | 235 | 256 | 257 | 266 | 269 | 280 | 311 | 312 | 313 | 316 | 419
        | 430 | 434 | 444 | 451 | 472 | 501 | 522 | 525 | 539 | 579 | 598 | 602 | 642 | 646
        | 650 | 653 | 656 | 657 | 799 | 807 | 840 | 841 | 927 | 1021 | 1173 => A04,

        // A05 — Security Misconfiguration
        2 | 11 | 13 | 15 | 16 | 260 | 315 | 520 | 526 | 537 | 541 | 547 | 611 | 614 | 756 | 776
        | 942 | 1004 | 1032 | 1174 => A05,

        // A06 — Vulnerable and Outdated Components
        937 | 1035 | 1104 => A06,

        // A07 — Identification and Authentication Failures
        255 | 259 | 287 | 288 | 290 | 294 | 295 | 297 | 300 | 302 | 303 | 304 | 306 | 307 | 346
        | 384 | 521 | 549 | 555 | 593 | 613 | 620 | 640 | 798 | 940 | 1216 => A07,

        // A08 — Software and Data Integrity Failures
        345 | 353 | 426 | 494 | 502 | 565 | 784 | 829 | 830 | 915 | 1357 => A08,

        // A09 — Security Logging and Monitoring Failures
        117 | 223 | 532 | 778 => A09,

        // A10 — SSRF
        918 => A10,

        // Common Heimdall hits not in the canonical OWASP cross-reference but
        // worth pinning to the closest category:
        190 => A04, // Integer overflow → typically a design/insecure-default issue
        489 => A05, // Active debug code → misconfiguration

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_cwes_to_correct_owasp_categories() {
        assert_eq!(lookup("CWE-89").unwrap().code, "A03:2021"); // SQL injection
        assert_eq!(lookup("CWE-78").unwrap().code, "A03:2021"); // OS command injection
        assert_eq!(lookup("CWE-22").unwrap().code, "A01:2021"); // Path traversal
        assert_eq!(lookup("CWE-639").unwrap().code, "A01:2021"); // IDOR
        assert_eq!(lookup("CWE-321").unwrap().code, "A02:2021"); // Hard-coded crypto key
        assert_eq!(lookup("CWE-798").unwrap().code, "A07:2021"); // Hard-coded credentials
        assert_eq!(lookup("CWE-327").unwrap().code, "A02:2021"); // Broken crypto
        assert_eq!(lookup("CWE-79").unwrap().code, "A03:2021"); // XSS
        assert_eq!(lookup("CWE-918").unwrap().code, "A10:2021"); // SSRF
        assert_eq!(lookup("CWE-829").unwrap().code, "A08:2021"); // Untrusted dependency
        assert_eq!(lookup("CWE-532").unwrap().code, "A09:2021"); // Logging sensitive info
    }

    #[test]
    fn accepts_bare_number_or_lowercase_prefix() {
        assert_eq!(lookup("89").unwrap().code, "A03:2021");
        assert_eq!(lookup("cwe-89").unwrap().code, "A03:2021");
        assert_eq!(lookup("  CWE-89  ").unwrap().code, "A03:2021");
    }

    #[test]
    fn returns_none_for_unmapped_or_invalid_input() {
        assert!(lookup("CWE-99999").is_none());
        assert!(lookup("not a cwe").is_none());
        assert!(lookup("").is_none());
    }
}
