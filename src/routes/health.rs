//
//  heimdall
//  src/routes/health.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::{web, HttpResponse};

use crate::models::ApiResponse;
use crate::state::AppState;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/health").route(web::get().to(health_check)));
}

async fn health_check(state: web::Data<AppState>) -> HttpResponse {
    match state.db.health_check().await {
        Ok(_) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "status": "healthy",
            "version": env!("CARGO_PKG_VERSION"),
        }))),
        Err(e) => HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
            503,
            format!("Unhealthy: {e}"),
        )),
    }
}
