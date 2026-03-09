//
//  heimdall
//  src/state.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::sync::Arc;

use crate::config::Config;
use crate::db::DatabaseOperations;

pub struct AppState {
    pub config: Arc<Config>,
    pub db: Arc<DatabaseOperations>,
}

impl AppState {
    pub fn init(config: Config, db: DatabaseOperations) -> Self {
        Self {
            config: Arc::new(config),
            db: Arc::new(db),
        }
    }
}
