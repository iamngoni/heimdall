//
//  heimdall
//  src/middleware/auth.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header;
use actix_web::{Error, HttpMessage, HttpResponse, web};
use chrono::Utc;
use log::warn;
use std::cell::RefCell;
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;
use uuid::Uuid;

use crate::auth;
use crate::models::ApiResponse;
use crate::state::AppState;

/// The session cookie name.
pub const SESSION_COOKIE_NAME: &str = "heimdall_session";

/// Authenticated user data attached to request extensions.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub role: String,
}

/// Middleware that enforces session-based authentication.
///
/// Extracts a session token from either `Authorization: Bearer <token>` or
/// the `heimdall_session` cookie, validates it against the database, and
/// attaches an `AuthenticatedUser` to the request extensions.
///
/// For API routes (`/api/*`, `/auth/*`), returns 401 JSON on failure.
/// For page routes, redirects to `/login`.
pub struct RequireAuth;

impl<S, B> Transform<S, ServiceRequest> for RequireAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = RequireAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequireAuthMiddleware {
            service: Rc::new(RefCell::new(service)),
        }))
    }
}

pub struct RequireAuthMiddleware<S> {
    service: Rc<RefCell<S>>,
}

/// Extract the session token from the request.
///
/// Checks `Authorization: Bearer <token>` first, then falls back to the
/// `heimdall_session` cookie.
fn extract_token(req: &ServiceRequest) -> Option<String> {
    // Try Authorization header first
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(value) = auth_header.to_str() {
            if let Some(token) = value.strip_prefix("Bearer ") {
                let token = token.trim();
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
    }

    // Fall back to cookie
    if let Some(cookie) = req.cookie(SESSION_COOKIE_NAME) {
        let value = cookie.value().trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }

    None
}

/// Determine whether the request targets an API route.
fn is_api_route(req: &ServiceRequest) -> bool {
    req.path().starts_with("/api/") || req.path().starts_with("/auth/")
}

/// Paths that should bypass authentication entirely.
/// These are public routes that happen to live under /api but don't require a session.
fn is_auth_exempt(path: &str) -> bool {
    path.starts_with("/api/auth/")
        || path == "/api/auth"
        || path.starts_with("/webhooks/")
        || path == "/health"
}

/// Build an error response for the appropriate route type.
fn auth_error<B>(req: ServiceRequest, is_api: bool, msg: &str) -> ServiceResponse<EitherBody<B>> {
    if is_api {
        let response = HttpResponse::Unauthorized().json(ApiResponse::<()>::error(401, msg));
        req.into_response(response).map_into_right_body()
    } else {
        let response = HttpResponse::Found()
            .insert_header((header::LOCATION, "/login"))
            .finish();
        req.into_response(response).map_into_right_body()
    }
}

fn server_error<B>(req: ServiceRequest) -> ServiceResponse<EitherBody<B>> {
    let response = HttpResponse::InternalServerError()
        .json(ApiResponse::<()>::error(500, "Internal server error"));
    req.into_response(response).map_into_right_body()
}

impl<S, B> Service<ServiceRequest> for RequireAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), Self::Error>> {
        self.service.borrow_mut().poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_string();
        let token = extract_token(&req);
        let is_api = is_api_route(&req);
        let app_state = req.app_data::<web::Data<AppState>>().cloned();
        let service = self.service.clone();

        Box::pin(async move {
            // Skip auth for public API routes (OAuth callbacks, login, register, webhooks)
            if is_auth_exempt(&path) {
                let res = service.borrow_mut().call(req).await?;
                return Ok(res.map_into_left_body());
            }

            // 1. Extract token
            let Some(token) = token else {
                return Ok(auth_error(req, is_api, "Authentication required"));
            };

            // 2. Get app state
            let Some(state) = app_state else {
                warn!("AppState not available in auth middleware");
                return Ok(server_error(req));
            };

            // 3. Look up session by token hash
            let token_hash = auth::hash_token(&token);
            let session = match state.db.get_session_by_token_hash(&token_hash).await {
                Ok(Some(session)) => session,
                Ok(None) => {
                    return Ok(auth_error(req, is_api, "Invalid or expired session"));
                }
                Err(e) => {
                    warn!("Failed to look up session: {e:#}");
                    return Ok(server_error(req));
                }
            };

            // 4. Check expiry (belt-and-suspenders — SQL query also filters)
            if session.expires_at < Utc::now() {
                return Ok(auth_error(req, is_api, "Session expired"));
            }

            // 5. Load user
            let user = match state.db.get_user_by_id(session.user_id).await {
                Ok(Some(user)) => user,
                Ok(None) => {
                    warn!("Session references non-existent user {}", session.user_id);
                    return Ok(auth_error(req, is_api, "User not found"));
                }
                Err(e) => {
                    warn!("Failed to load user: {e:#}");
                    return Ok(server_error(req));
                }
            };

            // 6. Attach authenticated user to request extensions
            let authenticated = AuthenticatedUser {
                id: user.id,
                email: user.email,
                display_name: user.display_name,
                role: user.role,
            };
            req.extensions_mut().insert(authenticated);

            // 7. Call the inner service
            let res = service.borrow_mut().call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}
