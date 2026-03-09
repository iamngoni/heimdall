//
//  heimdall
//  src/routes/mod.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

pub mod auth;
pub mod findings;
pub mod health;
pub mod pages;
pub mod repos;
pub mod scans;
pub mod settings;

use actix_web::web::ServiceConfig;

pub fn init(cfg: &mut ServiceConfig) {
    health::init(cfg);
    auth::init(cfg);
    pages::init(cfg);
    repos::init(cfg);
    scans::init(cfg);
    findings::init(cfg);
    settings::init(cfg);
}
