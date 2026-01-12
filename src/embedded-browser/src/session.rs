/*
 * Himmelblau Embedded Browser Service - Session Management
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Represents an active browser session
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BrowserSession {
    pub session_id: String,
    pub url: String,
    pub vnc_port: u16,
    pub width: u32,
    pub height: u32,
    pub container_ip: String,
    pub created_at: Instant,
    pub timeout_secs: u64,
}

impl BrowserSession {
    pub fn new(
        session_id: String,
        url: String,
        vnc_port: u16,
        width: u32,
        height: u32,
        container_ip: String,
        timeout_secs: u64,
    ) -> Self {
        Self {
            session_id,
            url,
            vnc_port,
            width,
            height,
            container_ip,
            created_at: Instant::now(),
            timeout_secs,
        }
    }

    /// Check if the session has timed out
    #[allow(dead_code)]
    pub fn is_timed_out(&self) -> bool {
        self.created_at.elapsed() > Duration::from_secs(self.timeout_secs)
    }

    /// Get remaining time before timeout in seconds
    #[allow(dead_code)]
    pub fn remaining_secs(&self) -> u64 {
        let elapsed = self.created_at.elapsed().as_secs();
        if elapsed >= self.timeout_secs {
            0
        } else {
            self.timeout_secs - elapsed
        }
    }
}

/// Manages all active browser sessions
pub struct SessionManager {
    sessions: HashMap<String, BrowserSession>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Add a new session
    pub fn add_session(&mut self, session: BrowserSession) {
        self.sessions.insert(session.session_id.clone(), session);
    }

    /// Remove a session
    pub fn remove_session(&mut self, session_id: &str) -> Option<BrowserSession> {
        self.sessions.remove(session_id)
    }

    /// Get a session by ID
    pub fn get_session(&self, session_id: &str) -> Option<&BrowserSession> {
        self.sessions.get(session_id)
    }

    /// Get all session IDs
    pub fn get_session_ids(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }

    /// Get all timed out sessions
    #[allow(dead_code)]
    pub fn get_timed_out_sessions(&self) -> Vec<String> {
        self.sessions
            .iter()
            .filter(|(_, s)| s.is_timed_out())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Remove all timed out sessions and return their IDs
    #[allow(dead_code)]
    pub fn remove_timed_out_sessions(&mut self) -> Vec<String> {
        let timed_out: Vec<String> = self.get_timed_out_sessions();
        for id in &timed_out {
            self.sessions.remove(id);
        }
        timed_out
    }

    /// Get the number of active sessions
    #[allow(dead_code)]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Check if a session exists
    #[allow(dead_code)]
    pub fn has_session(&self, session_id: &str) -> bool {
        self.sessions.contains_key(session_id)
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = BrowserSession::new(
            "test-session".to_string(),
            "https://example.com".to_string(),
            5900,
            800,
            600,
            300,
        );

        assert_eq!(session.session_id, "test-session");
        assert_eq!(session.url, "https://example.com");
        assert_eq!(session.vnc_port, 5900);
        assert_eq!(session.width, 800);
        assert_eq!(session.height, 600);
        assert!(!session.is_timed_out());
    }

    #[test]
    fn test_session_manager() {
        let mut manager = SessionManager::new();

        let session = BrowserSession::new(
            "test-session".to_string(),
            "https://example.com".to_string(),
            5900,
            800,
            600,
            300,
        );

        manager.add_session(session);
        assert!(manager.has_session("test-session"));
        assert_eq!(manager.session_count(), 1);

        let retrieved = manager.get_session("test-session");
        assert!(retrieved.is_some());

        manager.remove_session("test-session");
        assert!(!manager.has_session("test-session"));
        assert_eq!(manager.session_count(), 0);
    }
}
