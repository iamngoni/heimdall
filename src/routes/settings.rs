//
//  heimdall
//  src/routes/settings.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::{web, HttpResponse};

use crate::models::ApiResponse;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/settings")
            .route("", web::get().to(get_settings))
            .route("", web::put().to(update_settings))
            .route("/ai/test", web::post().to(test_ai_connection)),
    );
}

async fn get_settings() -> HttpResponse {
    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "message": "Settings — not yet implemented"
    })))
}

async fn update_settings() -> HttpResponse {
    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "message": "Update settings — not yet implemented"
    })))
}

async fn test_ai_connection() -> HttpResponse {
    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "message": "AI connection test — not yet implemented"
    })))
}
