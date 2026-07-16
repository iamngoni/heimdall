//
//  heimdall
//  src/middleware/csrf.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::body::EitherBody;
use actix_web::cookie::time::Duration;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::Method;
use actix_web::{Error, HttpResponse};
use log::debug;
use rand::Rng;
use std::cell::RefCell;
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;

/// Paths that are exempt from CSRF verification.
const CSRF_EXEMPT_PATHS: &[&str] = &["/health", "/api/auth/login", "/api/auth/register"];

/// Methods that require CSRF verification.
fn requires_csrf_check(method: &Method) -> bool {
    matches!(method, &Method::POST | &Method::PATCH | &Method::DELETE)
}

/// Check if the path starts with any exempt prefix.
fn is_exempt_path(path: &str) -> bool {
    CSRF_EXEMPT_PATHS.contains(&path) || path.starts_with("/api/webhooks/")
}

/// Extract the `_csrf` token from a URL query string.
///
/// Native form submissions cannot set an `X-CSRF-Token` header, so the token
/// is carried as a query parameter instead (the `_csrf` cookie is still sent
/// automatically, preserving the double-submit comparison). Tokens are hex, so
/// no percent-decoding is required.
fn query_csrf_token(query: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == "_csrf").then(|| value.to_string())
    })
}

/// Check if the request has a valid Bearer token (API clients skip CSRF).
fn has_bearer_token(req: &ServiceRequest) -> bool {
    req.headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("Bearer "))
        .unwrap_or(false)
}

/// Generate a random 32-byte hex CSRF token.
fn generate_csrf_token() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Double-submit cookie CSRF protection middleware.
pub struct CsrfProtection;

impl<S, B> Transform<S, ServiceRequest> for CsrfProtection
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = CsrfMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CsrfMiddleware {
            service: Rc::new(RefCell::new(service)),
        }))
    }
}

pub struct CsrfMiddleware<S> {
    service: Rc<RefCell<S>>,
}

impl<S, B> Service<ServiceRequest> for CsrfMiddleware<S>
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
        let method = req.method().clone();
        let path = req.path().to_string();
        let has_bearer = has_bearer_token(&req);

        // Extract cookie and header values for CSRF check
        let cookie_token = req.cookie("_csrf").map(|c| c.value().to_string());
        let header_token = req
            .headers()
            .get("X-CSRF-Token")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        // Native form submits carry the token as a query param (no custom headers).
        let query_token = query_csrf_token(req.query_string());

        let service = self.service.clone();

        Box::pin(async move {
            // Check CSRF for state-changing methods
            if requires_csrf_check(&method) && !is_exempt_path(&path) && !has_bearer {
                // Accept the token from the header (HTMX/fetch) or the query
                // string (native form submit). Either must match the cookie.
                let submitted = header_token.as_ref().or(query_token.as_ref());
                let valid = match (&cookie_token, submitted) {
                    (Some(cookie), Some(token)) if !cookie.is_empty() => cookie == token,
                    _ => false,
                };

                if !valid {
                    debug!("CSRF validation failed for {} {}", method, path);
                    let response = HttpResponse::Forbidden().json(serde_json::json!({
                        "success": false,
                        "error": "CSRF token mismatch"
                    }));
                    return Ok(req.into_response(response).map_into_right_body());
                }
            }

            // Call the inner service — borrow must be dropped before .await
            let needs_csrf_cookie = cookie_token.is_none();
            let fut = service.borrow_mut().call(req);
            let res = fut.await?;

            // If no _csrf cookie exists, set one on the response
            if needs_csrf_cookie {
                let token = generate_csrf_token();
                let cookie = Cookie::build("_csrf", token)
                    .path("/")
                    .same_site(SameSite::Strict)
                    .http_only(false) // JS/HTMX needs to read it
                    .max_age(Duration::hours(24))
                    .finish();

                let mut res = res.map_into_left_body();
                res.response_mut().add_cookie(&cookie).ok();
                Ok(res)
            } else {
                Ok(res.map_into_left_body())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::cookie::Cookie;
    use actix_web::http::StatusCode;
    use actix_web::test::{TestRequest, call_service, init_service};
    use actix_web::{App, HttpResponse, web};

    async fn ok() -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    #[test]
    fn query_csrf_token_extracts_value() {
        assert_eq!(query_csrf_token("_csrf=abc123").as_deref(), Some("abc123"));
        assert_eq!(
            query_csrf_token("foo=1&_csrf=abc&bar=2").as_deref(),
            Some("abc")
        );
        assert_eq!(query_csrf_token("foo=1"), None);
        assert_eq!(query_csrf_token(""), None);
    }

    #[actix_rt::test]
    async fn native_form_submit_with_matching_query_token_passes() {
        let app =
            init_service(App::new().wrap(CsrfProtection).route("/api/x", web::post().to(ok)))
                .await;
        let req = TestRequest::post()
            .uri("/api/x?_csrf=tok")
            .cookie(Cookie::new("_csrf", "tok"))
            .to_request();
        let resp = call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_rt::test]
    async fn post_without_any_token_is_rejected() {
        let app =
            init_service(App::new().wrap(CsrfProtection).route("/api/x", web::post().to(ok)))
                .await;
        let req = TestRequest::post()
            .uri("/api/x")
            .cookie(Cookie::new("_csrf", "tok"))
            .to_request();
        let resp = call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_rt::test]
    async fn mismatched_query_token_is_rejected() {
        let app =
            init_service(App::new().wrap(CsrfProtection).route("/api/x", web::post().to(ok)))
                .await;
        let req = TestRequest::post()
            .uri("/api/x?_csrf=wrong")
            .cookie(Cookie::new("_csrf", "tok"))
            .to_request();
        let resp = call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_rt::test]
    async fn header_token_still_works() {
        let app =
            init_service(App::new().wrap(CsrfProtection).route("/api/x", web::post().to(ok)))
                .await;
        let req = TestRequest::post()
            .uri("/api/x")
            .cookie(Cookie::new("_csrf", "tok"))
            .insert_header(("X-CSRF-Token", "tok"))
            .to_request();
        let resp = call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
