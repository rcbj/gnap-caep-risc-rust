// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

mod client;
mod config;
mod ssf;
mod subject;

trait MustErr<T> {
    fn must_err(self) -> crate::Error;
}

impl<T> MustErr<T> for Result<T, crate::Error> {
    fn must_err(self) -> crate::Error {
        match self {
            Err(err) => err,
            Ok(_) => panic!("expected an error"),
        }
    }
}
