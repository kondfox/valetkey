//! A short-lived, single-flight cache of fetched secrets (§6.7 step 4).
//!
//! - The key includes the config hash, so a new approval never reuses an old secret.
//! - Concurrent calls for one key wait for a single fetch instead of each spawning a `gcloud`.
//! - Failures aren't cached, and nothing retries.
//! - **Policy runs before the cache**, on every call: the broker asks the cache only after it has
//!   decided the secret may be used. A hit never skips policy.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use valetkey_core::secret_source::SourceError;

/// How long a fetched secret is reused.
pub const DEFAULT_TTL: Duration = Duration::from_secs(5 * 60);

/// Identifies one cached secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub project_key: String,
    pub config_hash: String,
    pub target: String,
    pub reference: String,
}

#[derive(Debug)]
struct Entry {
    value: SecretString,
    fetched_at: Instant,
}

type Slot = Arc<tokio::sync::Mutex<Option<Entry>>>;

#[derive(Debug)]
pub struct SecretCache {
    ttl: Duration,
    slots: Mutex<HashMap<CacheKey, Slot>>,
}

impl Default for SecretCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL)
    }
}

impl SecretCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// The cached value, or the result of `fetch` (cached on success).
    pub async fn get_or_fetch<F, Fut>(&self, key: CacheKey, fetch: F) -> Result<SecretString, SourceError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<SecretString, SourceError>>,
    {
        let slot = {
            let mut slots = self.slots.lock().expect("cache lock");
            // Drop expired entries that nobody is fetching right now, so config changes don't
            // grow the map for the broker's lifetime.
            if slots.len() > 32 {
                let ttl = self.ttl;
                slots.retain(|_, s| {
                    s.try_lock()
                        .map_or(true, |e| e.as_ref().is_some_and(|e| e.fetched_at.elapsed() < ttl))
                });
            }
            slots.entry(key).or_default().clone()
        };
        let mut entry = slot.lock().await;
        if let Some(e) = entry.as_ref()
            && e.fetched_at.elapsed() < self.ttl
        {
            return Ok(e.value.clone());
        }
        *entry = None;
        let value = fetch().await?;
        *entry = Some(Entry {
            value: value.clone(),
            fetched_at: Instant::now(),
        });
        Ok(value)
    }

    /// Drops a cached secret, e.g. after the server rejected it.
    pub fn invalidate(&self, key: &CacheKey) {
        self.slots.lock().expect("cache lock").remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn key(hash: &str) -> CacheKey {
        CacheKey {
            project_key: "p".into(),
            config_hash: hash.into(),
            target: "t".into(),
            reference: "local://x".into(),
        }
    }

    #[tokio::test]
    async fn concurrent_calls_share_one_fetch() {
        let cache = Arc::new(SecretCache::default());
        let fetches = Arc::new(AtomicUsize::new(0));
        let calls = (0..8).map(|_| {
            let (cache, fetches) = (cache.clone(), fetches.clone());
            tokio::spawn(async move {
                cache
                    .get_or_fetch(key("h"), || async {
                        fetches.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok(SecretString::from("s"))
                    })
                    .await
                    .unwrap()
                    .expose_secret()
                    .to_owned()
            })
        });
        for c in calls {
            assert_eq!(c.await.unwrap(), "s");
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_new_config_hash_misses_and_failures_arent_cached() {
        let cache = SecretCache::default();
        let n = AtomicUsize::new(0);
        let fetch = || async {
            n.fetch_add(1, Ordering::SeqCst);
            Ok(SecretString::from("s"))
        };
        cache.get_or_fetch(key("h1"), fetch).await.unwrap();
        cache.get_or_fetch(key("h1"), fetch).await.unwrap();
        cache.get_or_fetch(key("h2"), fetch).await.unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 2);

        let failing = || async { Err(SourceError::new("nope", "")) };
        assert!(cache.get_or_fetch(key("h3"), failing).await.is_err());
        cache.get_or_fetch(key("h3"), fetch).await.unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 3, "the failure wasn't cached");
    }

    #[tokio::test]
    async fn invalidating_during_a_fetch_doesnt_keep_the_old_value() {
        let cache = Arc::new(SecretCache::default());
        let n = Arc::new(AtomicUsize::new(0));
        let (c, n2) = (cache.clone(), n.clone());
        let slow = tokio::spawn(async move {
            c.get_or_fetch(key("h"), || async move {
                n2.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(SecretString::from("old"))
            })
            .await
            .unwrap()
            .expose_secret()
            .to_owned()
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        cache.invalidate(&key("h"));
        assert_eq!(slow.await.unwrap(), "old", "the in-flight caller still gets its value");
        let fresh = cache
            .get_or_fetch(key("h"), || async { Ok(SecretString::from("new")) })
            .await
            .unwrap();
        assert_eq!(fresh.expose_secret(), "new", "the next call fetches again");
    }

    #[tokio::test]
    async fn entries_expire_and_can_be_invalidated() {
        let cache = SecretCache::new(Duration::from_millis(50));
        let n = AtomicUsize::new(0);
        let fetch = || async {
            n.fetch_add(1, Ordering::SeqCst);
            Ok(SecretString::from("s"))
        };
        cache.get_or_fetch(key("h"), fetch).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        cache.get_or_fetch(key("h"), fetch).await.unwrap();
        cache.invalidate(&key("h"));
        cache.get_or_fetch(key("h"), fetch).await.unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 3);
    }
}
