//
//  heimdall
//  src/config.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use anyhow::{Context, Result};
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub app: AppConfig,
    pub database: DatabaseConfig,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub port: u16,
    pub host: String,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Config {
            app: AppConfig::from_env()?,
            database: DatabaseConfig::from_env()?,
        })
    }
}

impl AppConfig {
    fn from_env() -> Result<Self> {
        Ok(AppConfig {
            port: env::var("APP_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse::<u16>()
                .context("APP_PORT must be a valid port number")?,
            host: env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
        })
    }
}

impl DatabaseConfig {
    fn from_env() -> Result<Self> {
        let url = env::var("DATABASE_URL")
            .context("DATABASE_URL must be set (e.g., postgres://user:pass@localhost:5432/heimdall)")?;
        Ok(DatabaseConfig { url })
    }
}
