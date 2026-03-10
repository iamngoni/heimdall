//
//  heimdall
//  src/models/api_response.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: u16,
    pub message: String,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(code: u16, message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(ApiError {
                code,
                message: message.into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_ok() {
        let resp = ApiResponse::ok("hello");
        assert!(resp.success);
        assert_eq!(resp.data, Some("hello"));
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_api_response_error() {
        let resp = ApiResponse::<()>::error(404, "Not found");
        assert!(!resp.success);
        assert!(resp.data.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, 404);
        assert_eq!(err.message, "Not found");
    }

    #[test]
    fn test_api_response_ok_serializes() {
        let resp = ApiResponse::ok(serde_json::json!({"key": "value"}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"key\":\"value\""));
        // error field should be omitted (skip_serializing_if)
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_api_response_error_serializes() {
        let resp = ApiResponse::<()>::error(500, "Internal error");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("\"code\":500"));
        // data field should be omitted
        assert!(!json.contains("\"data\""));
    }
}
