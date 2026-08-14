//! Error types for the proxy.

use std::error::Error as StdError;
use thiserror::Error;

/// Boxed error type used for error chaining across crate boundaries.
pub type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// Context wrapper that preserves an optional underlying source error.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct ErrorContext {
    message: String,
    #[source]
    source: Option<BoxError>,
}

impl ErrorContext {
    /// Create context error with an underlying source.
    pub fn with_source<E>(message: impl Into<String>, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

/// Proxy-specific errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProxyError {
    /// Network I/O error.
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(#[source] ErrorContext),

    /// Signaling/iroh error (transient, e.g., connection failed).
    #[error("Signaling error: {0}")]
    Signaling(String),

    /// Authentication failed (permanent, e.g., unauthorized key, server rejected).
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Connection lost during the session.
    #[error("Connection lost: {0}")]
    ConnectionLost(String),

    /// The server detected its own identity is a duplicate and self-blocked.
    /// Permanent: the id is recorded in the blocklist and future starts are
    /// refused until an operator resolves the conflict.
    #[error("Duplicate server identity: {0}")]
    DuplicateServerId(String),
}

impl ProxyError {
    /// Create a configuration error with preserved source.
    pub fn config_with_source<E>(message: impl Into<String>, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::Config(ErrorContext::with_source(message, source))
    }

    /// Whether this error is potentially recoverable by reconnecting.
    ///
    /// Transient (recoverable): `ConnectionLost`, `Network`, `Signaling` — a
    /// dropped/failed connection that a retry might fix. Permanent: `Config`
    /// (bad input) and `AuthenticationFailed` (the server rejected the credential —
    /// retrying with the same key is pointless).
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            ProxyError::ConnectionLost(_) | ProxyError::Network(_) | ProxyError::Signaling(_)
        )
    }
}

/// Result type alias for proxy operations.
pub type ProxyResult<T> = Result<T, ProxyError>;
