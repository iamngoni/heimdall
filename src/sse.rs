//
//  heimdall
//  src/sse.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::Utc;
use serde::Serialize;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// An SSE event emitted during scan progress.
#[derive(Debug, Clone, Serialize)]
pub struct ScanEvent {
    pub scan_id: Uuid,
    pub event_type: ScanEventType,
    pub data: serde_json::Value,
    pub timestamp: String,
}

/// The types of SSE events emitted during a scan.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanEventType {
    StatusChange,
    StageUpdate,
    FindingAdded,
    ScanComplete,
    Error,
}

impl ScanEventType {
    /// Returns the SSE `event:` field name.
    pub fn as_event_name(&self) -> &'static str {
        match self {
            ScanEventType::StatusChange => "status_change",
            ScanEventType::StageUpdate => "stage_update",
            ScanEventType::FindingAdded => "finding_added",
            ScanEventType::ScanComplete => "scan_complete",
            ScanEventType::Error => "error",
        }
    }
}

/// Manages per-scan SSE broadcast channels for fan-out to multiple clients.
pub struct ScanBroadcaster {
    channels: Mutex<HashMap<Uuid, broadcast::Sender<ScanEvent>>>,
    cancellation_tokens: Mutex<HashMap<Uuid, CancellationToken>>,
}

impl Default for ScanBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanBroadcaster {
    pub fn new() -> Self {
        Self {
            channels: Mutex::new(HashMap::new()),
            cancellation_tokens: Mutex::new(HashMap::new()),
        }
    }

    /// Create and register a cancellation token for a scan.
    pub fn register_cancellation_token(&self, scan_id: Uuid) -> CancellationToken {
        let token = CancellationToken::new();
        let mut tokens = self
            .cancellation_tokens
            .lock()
            .expect("cancellation tokens lock poisoned");
        tokens.insert(scan_id, token.clone());
        token
    }

    /// Cancel a running scan by signalling its cancellation token.
    pub fn cancel_scan(&self, scan_id: Uuid) -> bool {
        let tokens = self
            .cancellation_tokens
            .lock()
            .expect("cancellation tokens lock poisoned");
        if let Some(token) = tokens.get(&scan_id) {
            token.cancel();
            true
        } else {
            false
        }
    }

    /// Remove the cancellation token for a scan.
    pub fn cleanup_cancellation_token(&self, scan_id: Uuid) {
        let mut tokens = self
            .cancellation_tokens
            .lock()
            .expect("cancellation tokens lock poisoned");
        tokens.remove(&scan_id);
    }

    /// Subscribe to SSE events for a specific scan.
    /// Creates the channel if it does not yet exist.
    pub fn subscribe(&self, scan_id: Uuid) -> broadcast::Receiver<ScanEvent> {
        let mut channels = self.channels.lock().expect("SSE channels lock poisoned");
        let sender = channels
            .entry(scan_id)
            .or_insert_with(|| broadcast::channel(100).0);
        sender.subscribe()
    }

    /// Send an event to all subscribers of a scan.
    /// If no subscribers exist yet, a channel is created (the event will be buffered).
    pub fn send(&self, scan_id: Uuid, event: ScanEvent) {
        let channels = self.channels.lock().expect("SSE channels lock poisoned");
        if let Some(sender) = channels.get(&scan_id) {
            // Ignore send errors — they just mean no active receivers.
            let _ = sender.send(event);
        }
    }

    /// Remove the broadcast channel for a scan (call after scan completes).
    pub fn cleanup(&self, scan_id: Uuid) {
        let mut channels = self.channels.lock().expect("SSE channels lock poisoned");
        channels.remove(&scan_id);
    }

    // ------------------------------------------------------------------
    // Convenience helpers for emitting common events
    // ------------------------------------------------------------------

    /// Emit a status_change event.
    pub fn emit_status_change(&self, scan_id: Uuid, status: &str) {
        self.send(
            scan_id,
            ScanEvent {
                scan_id,
                event_type: ScanEventType::StatusChange,
                data: serde_json::json!({
                    "scan_id": scan_id,
                    "status": status,
                    "timestamp": Utc::now().to_rfc3339(),
                }),
                timestamp: Utc::now().to_rfc3339(),
            },
        );
    }

    /// Emit a stage_update event.
    pub fn emit_stage_update(&self, scan_id: Uuid, stage: &str, status: &str, error: Option<&str>) {
        let mut data = serde_json::json!({
            "scan_id": scan_id,
            "stage": stage,
            "status": status,
            "timestamp": Utc::now().to_rfc3339(),
        });
        if let Some(err) = error {
            data["error"] = serde_json::Value::String(err.to_string());
        }
        self.send(
            scan_id,
            ScanEvent {
                scan_id,
                event_type: ScanEventType::StageUpdate,
                data,
                timestamp: Utc::now().to_rfc3339(),
            },
        );
    }

    /// Emit a finding_added event.
    pub fn emit_finding_added(&self, scan_id: Uuid, finding_id: Uuid, title: &str, severity: &str) {
        self.send(
            scan_id,
            ScanEvent {
                scan_id,
                event_type: ScanEventType::FindingAdded,
                data: serde_json::json!({
                    "scan_id": scan_id,
                    "finding_id": finding_id,
                    "title": title,
                    "severity": severity,
                }),
                timestamp: Utc::now().to_rfc3339(),
            },
        );
    }

    /// Emit a scan_complete event with finding counts.
    pub fn emit_scan_complete(
        &self,
        scan_id: Uuid,
        finding_count: i32,
        critical: i32,
        high: i32,
        medium: i32,
        low: i32,
    ) {
        self.send(
            scan_id,
            ScanEvent {
                scan_id,
                event_type: ScanEventType::ScanComplete,
                data: serde_json::json!({
                    "scan_id": scan_id,
                    "finding_count": finding_count,
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low,
                    "timestamp": Utc::now().to_rfc3339(),
                }),
                timestamp: Utc::now().to_rfc3339(),
            },
        );
    }

    /// Emit an error event.
    pub fn emit_error(&self, scan_id: Uuid, message: &str) {
        self.send(
            scan_id,
            ScanEvent {
                scan_id,
                event_type: ScanEventType::Error,
                data: serde_json::json!({
                    "scan_id": scan_id,
                    "error": message,
                    "timestamp": Utc::now().to_rfc3339(),
                }),
                timestamp: Utc::now().to_rfc3339(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_event_type_names() {
        assert_eq!(ScanEventType::StatusChange.as_event_name(), "status_change");
        assert_eq!(ScanEventType::StageUpdate.as_event_name(), "stage_update");
        assert_eq!(ScanEventType::FindingAdded.as_event_name(), "finding_added");
        assert_eq!(ScanEventType::ScanComplete.as_event_name(), "scan_complete");
        assert_eq!(ScanEventType::Error.as_event_name(), "error");
    }

    #[test]
    fn test_broadcaster_subscribe_and_receive() {
        let broadcaster = ScanBroadcaster::new();
        let scan_id = Uuid::now_v7();
        let mut rx = broadcaster.subscribe(scan_id);

        broadcaster.emit_status_change(scan_id, "running");

        let event = rx.try_recv().unwrap();
        assert_eq!(event.scan_id, scan_id);
        assert_eq!(event.event_type, ScanEventType::StatusChange);
    }

    #[test]
    fn test_broadcaster_no_subscribers_does_not_panic() {
        let broadcaster = ScanBroadcaster::new();
        let scan_id = Uuid::now_v7();
        // Sending without subscribers should not panic or error
        broadcaster.emit_status_change(scan_id, "running");
    }

    #[test]
    fn test_broadcaster_cleanup() {
        let broadcaster = ScanBroadcaster::new();
        let scan_id = Uuid::now_v7();
        let _rx = broadcaster.subscribe(scan_id);

        broadcaster.cleanup(scan_id);
        // After cleanup, sending should silently drop the event
        broadcaster.emit_status_change(scan_id, "running");
    }

    #[test]
    fn test_broadcaster_multiple_scans() {
        let broadcaster = ScanBroadcaster::new();
        let scan_a = Uuid::now_v7();
        let scan_b = Uuid::now_v7();
        let mut rx_a = broadcaster.subscribe(scan_a);
        let mut rx_b = broadcaster.subscribe(scan_b);

        broadcaster.emit_status_change(scan_a, "running");

        assert!(rx_a.try_recv().is_ok());
        // scan_b should not receive scan_a's events
        assert!(rx_b.try_recv().is_err());
    }

    #[test]
    fn test_emit_stage_update() {
        let broadcaster = ScanBroadcaster::new();
        let scan_id = Uuid::now_v7();
        let mut rx = broadcaster.subscribe(scan_id);

        broadcaster.emit_stage_update(scan_id, "ingest", "running", None);

        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_type, ScanEventType::StageUpdate);
        assert_eq!(event.data["stage"], "ingest");
    }

    #[test]
    fn test_emit_stage_update_with_error() {
        let broadcaster = ScanBroadcaster::new();
        let scan_id = Uuid::now_v7();
        let mut rx = broadcaster.subscribe(scan_id);

        broadcaster.emit_stage_update(scan_id, "hunt", "failed", Some("timeout"));

        let event = rx.try_recv().unwrap();
        assert_eq!(event.data["error"], "timeout");
    }

    #[test]
    fn test_emit_finding_added() {
        let broadcaster = ScanBroadcaster::new();
        let scan_id = Uuid::now_v7();
        let finding_id = Uuid::now_v7();
        let mut rx = broadcaster.subscribe(scan_id);

        broadcaster.emit_finding_added(scan_id, finding_id, "SQL Injection", "critical");

        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_type, ScanEventType::FindingAdded);
        assert_eq!(event.data["severity"], "critical");
    }

    #[test]
    fn test_emit_scan_complete() {
        let broadcaster = ScanBroadcaster::new();
        let scan_id = Uuid::now_v7();
        let mut rx = broadcaster.subscribe(scan_id);

        broadcaster.emit_scan_complete(scan_id, 10, 2, 3, 4, 1);

        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_type, ScanEventType::ScanComplete);
        assert_eq!(event.data["finding_count"], 10);
        assert_eq!(event.data["critical"], 2);
    }
}
