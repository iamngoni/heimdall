//
//  heimdall
//  src/routes/pages.rs
//
//  Created by Heimdall on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::{web, HttpResponse};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/pages")
            .route("/login", web::get().to(login_page))
            .route("/repos", web::get().to(repos_page))
            .route("/settings", web::get().to(settings_page)),
    );
}

async fn login_page() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("<html><body><h1>Heimdall — Login</h1><p>Coming soon.</p></body></html>")
}

async fn repos_page() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("<html><body><h1>Heimdall — Repositories</h1><p>Coming soon.</p></body></html>")
}

async fn settings_page() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("<html><body><h1>Heimdall — Settings</h1><p>Coming soon.</p></body></html>")
}
