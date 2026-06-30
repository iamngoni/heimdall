//
//  heimdall
//  src/routes/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
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
pub mod threat_models;
pub mod webhooks;

use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::web;
use actix_web::web::ServiceConfig;

use crate::middleware::auth::RequireAuth;

pub fn init(cfg: &mut ServiceConfig) {
    // Public routes — no auth required
    health::init(cfg);
    pages::init_public(cfg);

    // Codex OAuth redirect target. The OpenAI client only allows
    // http://localhost:1455/auth/callback (or 1457), so the path is fixed.
    // Anonymous: the OAuth `state` param matches the request back to a
    // pending login stored at /api/settings/codex/authorize time.
    cfg.route("/auth/callback", web::get().to(settings::codex_callback));

    // xAI/Grok OAuth redirect target. The Grok client is registered for
    // http://127.0.0.1:56121/callback and is matched to a pending Settings
    // login by the OAuth `state` parameter.
    cfg.route("/callback", web::get().to(settings::xai_oauth_callback));

    // Rate limiter for auth endpoints: ~10 requests per 60 seconds per IP
    // replenish_interval_ms = 60_000 / 10 = 6_000ms (one token every 6 seconds)
    let auth_rate_limit = GovernorConfigBuilder::default()
        .milliseconds_per_request(6_000)
        .burst_size(10)
        .finish()
        .expect("Failed to build auth rate limiter config");

    // Single /api scope with nested sub-scopes for auth (public) and
    // protected routes. Using two separate web::scope("/api") blocks causes
    // the first to catch ALL /api/* requests and 404 for non-auth routes.
    cfg.service(
        web::scope("/api")
            // Public auth endpoints — rate limited, no session required
            .service(
                web::scope("/auth")
                    .wrap(Governor::new(&auth_rate_limit))
                    .configure(auth::init_routes),
            )
            // Protected API routes — require a valid session
            .service(
                web::scope("")
                    .wrap(RequireAuth)
                    .configure(repos::init)
                    .configure(scans::init)
                    .configure(findings::init)
                    .configure(settings::init)
                    .configure(threat_models::init),
            ),
    );

    // Public webhook routes (signature-verified, not session-authenticated)
    cfg.service(web::scope("/webhooks").configure(webhooks::init));

    // Protected page routes — require a valid session (redirects to /login)
    // IMPORTANT: This catch-all scope ("") must be registered LAST so that
    // more-specific scopes (/api, /webhooks) are matched first.
    cfg.service(
        web::scope("")
            .wrap(RequireAuth)
            .configure(pages::init_protected),
    );

    // Default 404 handler for unmatched routes
    cfg.default_service(web::to(pages::default_not_found));
}
