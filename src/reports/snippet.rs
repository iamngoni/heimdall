//
//  heimdall
//  src/reports/snippet.rs
//
//  Created by Ngonidzashe Mangudya on 2026/05/04.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

//! Window a code snippet to a printable size.
//!
//! Real findings sometimes carry megabyte-scale snippets (minified JS, vendored
//! bundles). The PDF needs a fixed envelope around `line_start` plus a clear
//! "elided" marker so a reader knows the snippet was truncated.

const CONTEXT_LINES_BEFORE: usize = 12;
const CONTEXT_LINES_AFTER: usize = 18;
const MAX_LINE_BYTES: usize = 240;

/// A windowed view of a snippet, ready for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowedSnippet {
    /// Lines to render (each pre-truncated to a sane width).
    pub lines: Vec<RenderedLine>,
    /// True if some lines were dropped from the head or tail.
    pub truncated: bool,
    /// Total lines in the original snippet.
    pub original_line_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedLine {
    pub number: usize,
    pub text: String,
    /// True if `text` was truncated mid-line (e.g., one giant minified line).
    pub line_truncated: bool,
}

/// Window the snippet around the 1-based `focus_line`.
///
/// Returns up to `CONTEXT_LINES_BEFORE + CONTEXT_LINES_AFTER + 1` lines.
/// Each individual line is also clipped to `MAX_LINE_BYTES` to keep
/// minified-on-one-line files readable.
pub fn window(snippet: &str, focus_line: i32) -> WindowedSnippet {
    if snippet.is_empty() {
        return WindowedSnippet {
            lines: Vec::new(),
            truncated: false,
            original_line_count: 0,
        };
    }

    let all: Vec<&str> = snippet.split('\n').collect();
    let total = all.len();
    let focus = (focus_line.max(1) as usize).min(total.max(1));

    // Inclusive bounds (1-based numbering) of the window we'll keep.
    let start = focus.saturating_sub(CONTEXT_LINES_BEFORE).max(1);
    let end = (focus + CONTEXT_LINES_AFTER).min(total);

    let mut rendered = Vec::with_capacity(end - start + 1);
    for (idx, line) in all.iter().enumerate().take(end).skip(start - 1) {
        let (text, line_truncated) = clip_long_line(line);
        rendered.push(RenderedLine {
            number: idx + 1,
            text,
            line_truncated,
        });
    }

    let truncated = start > 1 || end < total;
    WindowedSnippet {
        lines: rendered,
        truncated,
        original_line_count: total,
    }
}

fn clip_long_line(line: &str) -> (String, bool) {
    if line.len() <= MAX_LINE_BYTES {
        return (line.to_string(), false);
    }
    // Snip on a UTF-8 char boundary.
    let mut cut = MAX_LINE_BYTES;
    while cut > 0 && !line.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = line[..cut].to_string();
    out.push_str(" …");
    (out, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snippet(lines: usize) -> String {
        (1..=lines)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn empty_snippet_returns_empty_window() {
        let w = window("", 1);
        assert!(w.lines.is_empty());
        assert!(!w.truncated);
        assert_eq!(w.original_line_count, 0);
    }

    #[test]
    fn small_snippet_returns_all_lines_untruncated() {
        let s = snippet(10);
        let w = window(&s, 5);
        assert_eq!(w.lines.len(), 10);
        assert!(!w.truncated);
        assert_eq!(w.lines[0].number, 1);
        assert_eq!(w.lines[9].number, 10);
    }

    #[test]
    fn large_snippet_windows_around_focus() {
        let s = snippet(1000);
        let w = window(&s, 500);
        assert!(w.truncated);
        // CONTEXT_LINES_BEFORE + 1 + CONTEXT_LINES_AFTER = 31
        assert_eq!(w.lines.len(), 31);
        assert_eq!(w.lines.first().unwrap().number, 488);
        assert_eq!(w.lines.last().unwrap().number, 518);
    }

    #[test]
    fn focus_at_start_clamps_lower_bound() {
        let s = snippet(1000);
        let w = window(&s, 1);
        assert_eq!(w.lines.first().unwrap().number, 1);
        assert!(w.truncated);
    }

    #[test]
    fn focus_past_end_clamps_to_last_line() {
        let s = snippet(50);
        let w = window(&s, 9999);
        assert_eq!(w.lines.last().unwrap().number, 50);
        // window is line 38..=50 (focus 50 - 12 = 38)
        assert_eq!(w.lines.first().unwrap().number, 38);
    }

    #[test]
    fn very_long_single_line_gets_clipped() {
        let huge = "x".repeat(10_000);
        let w = window(&huge, 1);
        assert_eq!(w.lines.len(), 1);
        assert!(w.lines[0].line_truncated);
        assert!(w.lines[0].text.len() < 300);
        assert!(w.lines[0].text.ends_with('…'));
    }

    #[test]
    fn line_clipping_preserves_utf8_boundary() {
        let line = "A".repeat(MAX_LINE_BYTES - 1) + "🔥".repeat(20).as_str();
        let w = window(&line, 1);
        // Should not panic and the clipped text must still be valid UTF-8.
        assert!(w.lines[0].line_truncated);
        // Round-trip through String to confirm valid UTF-8.
        let _ = w.lines[0].text.clone();
    }
}
