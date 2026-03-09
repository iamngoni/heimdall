//
//  heimdall
//  src/index/mod.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod callgraph;
pub mod deps;
pub mod search;
pub mod symbols;

/// Combined code index providing symbol lookup, call graph traversal,
/// dependency resolution, and full-text search across the scanned codebase.
pub struct CodeIndex {
    pub symbols: symbols::SymbolIndex,
    pub callgraph: callgraph::CallGraph,
    pub deps: deps::DependencyGraph,
    pub search: search::SearchIndex,
}

impl CodeIndex {
    pub fn new() -> Self {
        Self {
            symbols: symbols::SymbolIndex::new(),
            callgraph: callgraph::CallGraph::new(),
            deps: deps::DependencyGraph::new(),
            search: search::SearchIndex::new(),
        }
    }
}
