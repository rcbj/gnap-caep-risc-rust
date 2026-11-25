// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#[cfg(feature = "local")]
mod authzen;
mod client;
mod config;
mod install_script;
#[cfg(feature = "pep")]
mod pep;
mod ssf;
mod stub_realm;
mod subject;
mod trust_chain;

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
