//
//  heimdall
//  src/routes/auth.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::{web, HttpResponse};

use crate::models::ApiResponse;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/login", web::post().to(login))
            .route("/logout", web::post().to(logout))
            .route("/github/callback", web::get().to(github_callback))
            .route("/gitlab/callback", web::get().to(gitlab_callback)),
    );
}

async fn login() -> HttpResponse {
    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "message": "Login endpoint — not yet implemented"
    })))
}

async fn logout() -> HttpResponse {
    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "message": "Logout endpoint — not yet implemented"
    })))
}

async fn github_callback() -> HttpResponse {
    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "message": "GitHub OAuth callback — not yet implemented"
    })))
}

async fn gitlab_callback() -> HttpResponse {
    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "message": "GitLab OAuth callback — not yet implemented"
    })))
}
