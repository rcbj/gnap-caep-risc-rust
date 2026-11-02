// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

mod client;
mod codec;
mod config;
mod error;
mod http;
mod keys;
mod proof;
mod ssf;
mod subject;
mod urlutil;

pub use client::{Client, Finished, Grant, GrantResult, Pending};
pub use config::{resolve, Config, Display, SsfConfig};
pub use error::{Continuation, Error};
pub use http::{Answer, TlsOpt};
pub use keys::{fingerprint, load_client_key, public_key_object, ClientKey};
pub use proof::interaction_hash;
pub use ssf::{subject_of, verify_compact, EndFn, Events, HeaderFn, ReceiverOpt, SignalEvent, SignalsReceiver, TrackedSession, VerifiedJws};
pub use subject::{person_from, IdCheck, Person};

#[cfg(test)]
mod tests;

use std::sync::OnceLock;

pub(crate) fn provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: OnceLock<std::sync::Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            let provider = rustls::crypto::ring::default_provider();
            let _ = provider.clone().install_default();
            std::sync::Arc::new(provider)
        })
        .clone()
}
