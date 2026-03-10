//
//  heimdall
//  src/index/callgraph.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::collections::HashMap;

/// A call site: who calls whom, and where.
#[derive(Debug, Clone)]
pub struct CallEdge {
    pub caller: String,
    pub callee: String,
    pub file: String,
    pub line: usize,
}

/// Call graph mapping function call relationships across the codebase.
pub struct CallGraph {
    /// callee -> list of callers
    callers: HashMap<String, Vec<CallEdge>>,
    /// caller -> list of callees
    callees: HashMap<String, Vec<CallEdge>>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self {
            callers: HashMap::new(),
            callees: HashMap::new(),
        }
    }

    pub fn add_edge(&mut self, caller: &str, callee: &str, file: &str, line: usize) {
        let edge = CallEdge {
            caller: caller.to_string(),
            callee: callee.to_string(),
            file: file.to_string(),
            line,
        };
        self.callers
            .entry(callee.to_string())
            .or_default()
            .push(edge.clone());
        self.callees
            .entry(caller.to_string())
            .or_default()
            .push(edge);
    }

    /// Find all callers of a given function.
    pub fn get_callers(&self, symbol: &str) -> Vec<&CallEdge> {
        self.callers
            .get(symbol)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Find all functions called by a given function.
    pub fn get_callees(&self, symbol: &str) -> Vec<&CallEdge> {
        self.callees
            .get(symbol)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Format callers as a string for LLM context.
    pub fn callers_summary(&self, symbol: &str) -> String {
        let callers = self.get_callers(symbol);
        if callers.is_empty() {
            return format!("No callers found for `{symbol}`.");
        }
        let mut out = format!("Callers of `{symbol}`:\n");
        for edge in callers {
            out.push_str(&format!(
                "- `{}` at {}:{}\n",
                edge.caller, edge.file, edge.line
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_query_callees() {
        let mut graph = CallGraph::new();
        graph.add_edge("main", "helper", "src/main.rs", 5);
        graph.add_edge("main", "init", "src/main.rs", 6);

        let callees = graph.get_callees("main");
        assert_eq!(callees.len(), 2);
        let callee_names: Vec<&str> = callees.iter().map(|e| e.callee.as_str()).collect();
        assert!(callee_names.contains(&"helper"));
        assert!(callee_names.contains(&"init"));
    }

    #[test]
    fn test_add_and_query_callers() {
        let mut graph = CallGraph::new();
        graph.add_edge("main", "helper", "src/main.rs", 5);
        graph.add_edge("setup", "helper", "src/setup.rs", 10);

        let callers = graph.get_callers("helper");
        assert_eq!(callers.len(), 2);
        let caller_names: Vec<&str> = callers.iter().map(|e| e.caller.as_str()).collect();
        assert!(caller_names.contains(&"main"));
        assert!(caller_names.contains(&"setup"));
    }

    #[test]
    fn test_no_callers_returns_empty() {
        let graph = CallGraph::new();
        let callers = graph.get_callers("nonexistent");
        assert!(callers.is_empty());
    }

    #[test]
    fn test_no_callees_returns_empty() {
        let graph = CallGraph::new();
        let callees = graph.get_callees("nonexistent");
        assert!(callees.is_empty());
    }

    #[test]
    fn test_callers_summary_with_callers() {
        let mut graph = CallGraph::new();
        graph.add_edge("main", "helper", "src/main.rs", 5);

        let summary = graph.callers_summary("helper");
        assert!(summary.contains("main"));
        assert!(summary.contains("src/main.rs:5"));
    }

    #[test]
    fn test_callers_summary_no_callers() {
        let graph = CallGraph::new();
        let summary = graph.callers_summary("orphan");
        assert!(summary.contains("No callers found"));
    }

    #[test]
    fn test_edge_preserves_file_and_line() {
        let mut graph = CallGraph::new();
        graph.add_edge("caller", "callee", "src/lib.rs", 42);

        let callees = graph.get_callees("caller");
        assert_eq!(callees.len(), 1);
        assert_eq!(callees[0].file, "src/lib.rs");
        assert_eq!(callees[0].line, 42);
    }
}
