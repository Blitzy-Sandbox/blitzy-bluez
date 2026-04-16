// SPDX-License-Identifier: GPL-2.0-or-later
//
// Timeout abstractions replacing src/shared/timeout.h + timeout-mainloop.c
//
// C's timeout_add(msec, callback, user_data, destroy) is replaced by
// TimeoutHandle which wraps a tokio task with AbortHandle for cancellation.

use std::future::Future;
use std::time::Duration;

use tokio::task::AbortHandle;

/// Handle to a scheduled timeout. Dropping this does NOT cancel the timeout;
/// you must call `cancel()` explicitly (matching C's `timeout_remove` semantics).
#[derive(Debug)]
pub struct TimeoutHandle {
    abort: AbortHandle,
}

impl TimeoutHandle {
    /// Cancel the timeout. If the callback has already fired, this is a no-op.
    pub fn cancel(self) {
        self.abort.abort();
    }

    /// Check if the timeout has already been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.abort.is_finished()
    }
}

/// Schedule a one-shot timeout. The future `func` is executed after `duration`.
///
/// Replaces C's `timeout_add()`. Returns a handle that can cancel the timeout.
///
/// ```ignore
/// let handle = timeout_add(Duration::from_secs(5), async {
///     println!("timeout fired!");
/// });
/// // Later:
/// handle.cancel();
/// ```
pub fn timeout_add<F>(duration: Duration, func: F) -> TimeoutHandle
where
    F: Future<Output = ()> + Send + 'static,
{
    let handle = tokio::spawn(async move {
        tokio::time::sleep(duration).await;
        func.await;
    });
    TimeoutHandle {
        abort: handle.abort_handle(),
    }
}

/// Schedule a one-shot timeout with a synchronous callback.
pub fn timeout_add_sync<F>(duration: Duration, func: F) -> TimeoutHandle
where
    F: FnOnce() + Send + 'static,
{
    let handle = tokio::spawn(async move {
        tokio::time::sleep(duration).await;
        func();
    });
    TimeoutHandle {
        abort: handle.abort_handle(),
    }
}

/// Convenience: schedule a one-shot timeout in seconds.
///
/// Replaces C's `timeout_add_seconds()`.
pub fn timeout_add_seconds<F>(secs: u32, func: F) -> TimeoutHandle
where
    F: FnOnce() + Send + 'static,
{
    timeout_add_sync(Duration::from_secs(u64::from(secs)), func)
}

/// Schedule a repeating interval timer. The callback returns `true` to continue
/// or `false` to stop, matching the C pattern where `timeout_func_t` returns bool.
///
/// Replaces C's repeating timeout pattern (timeout_add + re-arm on callback return true).
pub fn interval_add<F>(duration: Duration, mut func: F) -> TimeoutHandle
where
    F: FnMut() -> bool + Send + 'static,
{
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(duration);
        // Skip the first immediate tick
        interval.tick().await;
        loop {
            interval.tick().await;
            if !func() {
                break;
            }
        }
    });
    TimeoutHandle {
        abort: handle.abort_handle(),
    }
}

/// Sleep for the given duration. Convenience wrapper around `tokio::time::sleep`.
pub async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

/// Sleep for the given number of milliseconds.
pub async fn sleep_ms(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_timeout_fires() {
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();

        let _handle = timeout_add_sync(Duration::from_millis(10), move || {
            fired_clone.store(true, Ordering::SeqCst);
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(fired.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_timeout_cancel() {
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();

        let handle = timeout_add_sync(Duration::from_millis(50), move || {
            fired_clone.store(true, Ordering::SeqCst);
        });

        handle.cancel();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!fired.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_timeout_add_seconds() {
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();

        // Use 0 seconds which should fire ~immediately (after one tick)
        let _handle = timeout_add_seconds(0, move || {
            fired_clone.store(true, Ordering::SeqCst);
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(fired.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_interval_fires_multiple() {
        let count = Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();

        let _handle = interval_add(Duration::from_millis(10), move || {
            let prev = count_clone.fetch_add(1, Ordering::SeqCst);
            prev < 2 // fire 3 times total (0, 1, 2), stop when prev==2
        });

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_interval_cancel() {
        let count = Arc::new(AtomicU32::new(0));
        let count_clone = count.clone();

        let handle = interval_add(Duration::from_millis(10), move || {
            count_clone.fetch_add(1, Ordering::SeqCst);
            true // keep going forever
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.cancel();
        let count_at_cancel = count.load(Ordering::SeqCst);

        tokio::time::sleep(Duration::from_millis(50)).await;
        let count_after = count.load(Ordering::SeqCst);

        // Count should not have increased much after cancel
        assert!(count_after <= count_at_cancel + 1);
        assert!(count_at_cancel > 0);
    }

    #[tokio::test]
    async fn test_async_timeout() {
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();

        let _handle = timeout_add(Duration::from_millis(10), async move {
            fired_clone.store(true, Ordering::SeqCst);
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(fired.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_sleep_ms() {
        let start = tokio::time::Instant::now();
        sleep_ms(10).await;
        assert!(start.elapsed() >= Duration::from_millis(10));
    }
}
