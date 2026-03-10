//
//  heimdall
//  src/models/pagination.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

impl PaginationParams {
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1).max(1)
    }

    pub fn per_page(&self) -> u32 {
        self.per_page.unwrap_or(25).min(100)
    }

    pub fn offset(&self) -> i64 {
        let page = self.page();
        let per_page = self.per_page();
        ((page - 1) as i64) * (per_page as i64)
    }

    pub fn limit(&self) -> i64 {
        self.per_page() as i64
    }
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
}

impl<T: Serialize> PaginatedResponse<T> {
    pub fn new(items: Vec<T>, total: i64, page: u32, per_page: u32) -> Self {
        let total_pages = if total == 0 {
            1
        } else {
            ((total as f64) / (per_page as f64)).ceil() as u32
        };
        Self {
            items,
            total,
            page,
            per_page,
            total_pages,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_defaults() {
        let params = PaginationParams {
            page: None,
            per_page: None,
        };
        assert_eq!(params.page(), 1);
        assert_eq!(params.per_page(), 25);
        assert_eq!(params.offset(), 0);
        assert_eq!(params.limit(), 25);
    }

    #[test]
    fn test_pagination_page_minimum() {
        let params = PaginationParams {
            page: Some(0),
            per_page: None,
        };
        assert_eq!(params.page(), 1); // Clamped to minimum 1
    }

    #[test]
    fn test_pagination_per_page_maximum() {
        let params = PaginationParams {
            page: None,
            per_page: Some(500),
        };
        assert_eq!(params.per_page(), 100); // Clamped to max 100
    }

    #[test]
    fn test_pagination_offset_calculation() {
        let params = PaginationParams {
            page: Some(3),
            per_page: Some(10),
        };
        assert_eq!(params.offset(), 20); // (3-1) * 10
        assert_eq!(params.limit(), 10);
    }

    #[test]
    fn test_paginated_response_total_pages() {
        let resp: PaginatedResponse<i32> = PaginatedResponse::new(vec![1, 2, 3], 25, 1, 10);
        assert_eq!(resp.total_pages, 3); // ceil(25/10) = 3
    }

    #[test]
    fn test_paginated_response_zero_total() {
        let resp: PaginatedResponse<i32> = PaginatedResponse::new(vec![], 0, 1, 10);
        assert_eq!(resp.total_pages, 1);
    }

    #[test]
    fn test_paginated_response_exact_division() {
        let resp: PaginatedResponse<i32> = PaginatedResponse::new(vec![], 20, 1, 10);
        assert_eq!(resp.total_pages, 2);
    }
}
