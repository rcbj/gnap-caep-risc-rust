// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::fmt;

#[derive(Debug, Clone)]
pub struct Continuation {
    pub uri: String,
    pub access_token: String,
    pub wait: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
    pub gnap: Option<String>,
    pub continuation: Option<Continuation>,
}

impl Error {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), gnap: None, continuation: None }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

pub(crate) fn fail(code: &'static str, message: impl Into<String>) -> Error {
    Error::new(code, message)
}
