//
//  heimdall
//  src/lib.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

#![allow(clippy::too_many_arguments)]
#![allow(clippy::vec_init_then_push)]

pub mod ai;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
pub mod errors;
pub mod index;
pub mod integrations;
pub mod mcp;
pub mod middleware;
pub mod models;
pub mod pipeline;
pub mod reports;
pub mod routes;
pub mod sse;
pub mod state;
pub mod templates;
pub mod util;
pub mod worker;
