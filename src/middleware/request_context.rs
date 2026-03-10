//
//  heimdall
//  src/middleware/request_context.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use actix_web::Error;
use actix_web::HttpMessage;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderName, HeaderValue};
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: String,
}

impl RequestContext {
    pub fn new() -> Self {
        Self {
            request_id: Uuid::now_v7().to_string(),
        }
    }
}

pub struct RequestContextMiddleware;

impl<S, B> Transform<S, ServiceRequest> for RequestContextMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequestContextMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestContextMiddlewareService { service }))
    }
}

pub struct RequestContextMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestContextMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let context = RequestContext::new();
        let request_id = context.request_id.clone();

        req.extensions_mut().insert(context);

        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;
            res.headers_mut().insert(
                HeaderName::from_static("x-request-id"),
                HeaderValue::from_str(&request_id)
                    .unwrap_or_else(|_| HeaderValue::from_static("unknown")),
            );
            Ok(res)
        })
    }
}
