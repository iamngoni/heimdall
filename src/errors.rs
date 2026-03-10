//
//  heimdall
//  src/errors.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::{HttpResponse, ResponseError, http::StatusCode};

#[derive(Debug, thiserror::Error)]
pub enum HeimdallError {
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("AI provider error: {0}")]
    Ai(String),

    #[error("Pipeline error at stage '{stage}': {message}")]
    Pipeline { stage: String, message: String },

    #[error("Docker error: {0}")]
    Docker(#[from] bollard::errors::Error),

    #[error("Git error: {0}")]
    Git(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Configuration error: {0}")]
    Config(#[from] anyhow::Error),
}

impl ResponseError for HeimdallError {
    fn status_code(&self) -> StatusCode {
        match self {
            HeimdallError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
            HeimdallError::Ai(_) => StatusCode::BAD_GATEWAY,
            HeimdallError::Pipeline { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            HeimdallError::Docker(_) => StatusCode::INTERNAL_SERVER_ERROR,
            HeimdallError::Git(_) => StatusCode::BAD_REQUEST,
            HeimdallError::Validation(_) => StatusCode::BAD_REQUEST,
            HeimdallError::Auth(_) => StatusCode::UNAUTHORIZED,
            HeimdallError::NotFound(_) => StatusCode::NOT_FOUND,
            HeimdallError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let body = serde_json::json!({
            "success": false,
            "error": {
                "code": status.as_u16(),
                "message": self.to_string()
            }
        });
        HttpResponse::build(status).json(body)
    }
}
