//! Logging infrastructure for service-gator operations.
//!
//! This module provides structured logging for all operations, with special emphasis
//! on write operations (git push, branch creation, PR creation, etc.) which are always
//! logged at INFO level. Read operations are aggregated and logged periodically
//! to reduce noise.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// Counter for tracking read-only operations.
///
/// This is used to aggregate read operations and log them periodically
/// rather than logging each one individually.
#[derive(Debug, Default)]
pub struct ReadOpCounter {
    count: AtomicU64,
}

impl ReadOpCounter {
    /// Increment the read operation counter.
    pub fn increment(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get and reset the counter, returning the previous value.
    pub fn take(&self) -> u64 {
        self.count.swap(0, Ordering::Relaxed)
    }
}

/// Shared state for the logging background task.
#[derive(Clone)]
pub struct LoggingState {
    pub read_ops: Arc<ReadOpCounter>,
    shutdown: Arc<Notify>,
}

impl Default for LoggingState {
    fn default() -> Self {
        Self::new()
    }
}

impl LoggingState {
    /// Create a new logging state.
    pub fn new() -> Self {
        Self {
            read_ops: Arc::new(ReadOpCounter::default()),
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Signal shutdown to the background logging task.
    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }

    /// Spawn the background task that periodically logs aggregated read operations.
    ///
    /// The task logs every `interval` seconds if there were any read operations.
    pub fn spawn_background_logger(self, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {
                        let count = self.read_ops.take();
                        if count > 0 {
                            tracing::info!(count = count, "read operations in last interval");
                        }
                    }
                    _ = self.shutdown.notified() => {
                        // Log any remaining operations before shutdown
                        let count = self.read_ops.take();
                        if count > 0 {
                            tracing::info!(count = count, "read operations (final)");
                        }
                        break;
                    }
                }
            }
        })
    }
}
