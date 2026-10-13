//! The ML tier runs on its own thread so a slow or stuck model can be timed
//! out. Results that arrive after the caller gave up still land in the ML
//! cache, so the next request with the same text is fast.
//!
//! The queue is bounded: when it is full a request is refused at once
//! instead of piling up behind a slow model. A caller that times out cancels
//! its job: the worker finishes the batch in progress (its results are
//! cached) and skips the rest, and skips a cancelled job still in the queue.
//! Before running the model the worker looks every text up in the ML cache,
//! so work another job finished meanwhile is not repeated.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crossbeam_channel::{RecvTimeoutError, Sender, TrySendError};
use parda_core::{Detection, MlDetector};

use crate::cache::{DetCache, Key};

/// Texts per `detect_batch` call; bounds peak memory of one inference.
const BATCH: usize = 8;
/// Pending jobs; beyond this a request is refused at once (strict mode: 503,
/// fast mode: rules only) instead of piling up behind a slow model.
const QUEUE_JOBS: usize = 16;

type Reply = anyhow::Result<Vec<Vec<Detection>>>;

struct Job {
    texts: Vec<String>,
    keys: Vec<Key>,
    reply: Sender<Reply>,
    cancelled: Arc<AtomicBool>,
}

pub(crate) struct MlWorker {
    tx: Sender<Job>,
    name: String,
}

impl MlWorker {
    pub(crate) fn spawn(det: Arc<dyn MlDetector>, cache: Arc<DetCache>) -> std::io::Result<Self> {
        let (tx, rx) = crossbeam_channel::bounded::<Job>(QUEUE_JOBS);
        let name = det.name().to_string();
        std::thread::Builder::new()
            .name("parda-ml".into())
            .spawn(move || {
                for job in rx {
                    if job.cancelled.load(Ordering::SeqCst) {
                        continue;
                    }
                    let res = run(det.as_ref(), &cache, &job);
                    let _ = job.reply.send(res);
                }
            })?;
        Ok(MlWorker { tx, name })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Detect in `texts`, waiting at most `timeout`. Errors are short
    /// descriptions without any input text.
    pub(crate) fn detect(
        &self,
        texts: Vec<String>,
        keys: Vec<Key>,
        timeout: Duration,
    ) -> Result<Vec<Vec<Detection>>, String> {
        let (reply, rx) = crossbeam_channel::bounded(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        self.tx
            .try_send(Job {
                texts,
                keys,
                reply,
                cancelled: cancelled.clone(),
            })
            .map_err(|e| match e {
                TrySendError::Full(_) => "ML detector busy (request queue full)".to_string(),
                TrySendError::Disconnected(_) => "ML worker stopped".to_string(),
            })?;
        match rx.recv_timeout(timeout) {
            Ok(Ok(d)) => Ok(d),
            Ok(Err(e)) => Err(format!("ML detector failed: {e:#}")),
            Err(RecvTimeoutError::Timeout) => {
                cancelled.store(true, Ordering::SeqCst);
                Err(format!(
                    "ML detector timed out after {} ms",
                    timeout.as_millis()
                ))
            }
            Err(RecvTimeoutError::Disconnected) => Err("ML worker stopped".to_string()),
        }
    }
}

fn run(det: &dyn MlDetector, cache: &DetCache, job: &Job) -> Reply {
    let mut out: Vec<Option<Vec<Detection>>> = job
        .keys
        .iter()
        .map(|k| cache.get(k).map(|d| d.as_ref().clone()))
        .collect();
    let todo: Vec<usize> = (0..out.len()).filter(|&i| out[i].is_none()).collect();
    for chunk in todo.chunks(BATCH) {
        if job.cancelled.load(Ordering::SeqCst) {
            anyhow::bail!("cancelled");
        }
        let refs: Vec<&str> = chunk.iter().map(|&i| job.texts[i].as_str()).collect();
        let got = catch_unwind(AssertUnwindSafe(|| det.detect_batch(&refs)))
            .map_err(|_| anyhow::anyhow!("ML detector panicked"))??;
        if got.len() != refs.len() {
            anyhow::bail!(
                "ML detector returned {} results for {} inputs",
                got.len(),
                refs.len()
            );
        }
        for (&i, d) in chunk.iter().zip(got) {
            cache.put(job.keys[i], Arc::new(d.clone()));
            out[i] = Some(d);
        }
    }
    Ok(out.into_iter().map(Option::unwrap_or_default).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Slow {
        delay: Duration,
        calls: AtomicUsize,
    }

    impl MlDetector for Slow {
        fn name(&self) -> &str {
            "slow"
        }
        fn detect_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<Detection>>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            Ok(vec![Vec::new(); texts.len()])
        }
    }

    fn worker(delay_ms: u64) -> (Arc<Slow>, MlWorker) {
        let det = Arc::new(Slow {
            delay: Duration::from_millis(delay_ms),
            calls: AtomicUsize::new(0),
        });
        let w = MlWorker::spawn(det.clone(), Arc::new(DetCache::new(100))).unwrap();
        (det, w)
    }

    fn job(n: usize, salt: &str) -> (Vec<String>, Vec<Key>) {
        let texts: Vec<String> = (0..n).map(|i| format!("{salt} text {i}")).collect();
        let keys = texts.iter().map(|t| crate::cache::key("t", 0, t)).collect();
        (texts, keys)
    }

    #[test]
    fn timed_out_job_stops_after_the_current_batch() {
        let (det, w) = worker(100);
        let (texts, keys) = job(3 * BATCH, "a");
        assert!(w.detect(texts, keys, Duration::from_millis(30)).is_err());
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(det.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn queue_is_bounded_and_abandoned_jobs_are_skipped() {
        let (det, w) = worker(300);
        let mut busy = false;
        for i in 0..QUEUE_JOBS + 8 {
            let (texts, keys) = job(1, &i.to_string());
            if let Err(e) = w.detect(texts, keys, Duration::from_millis(1)) {
                busy |= e.contains("busy");
            }
        }
        assert!(busy, "a full queue must refuse new work at once");
        std::thread::sleep(Duration::from_millis(500));
        assert!(det.calls.load(Ordering::SeqCst) <= 2);
    }

    #[test]
    fn worker_reuses_results_computed_meanwhile() {
        let (det, w) = worker(100);
        let w = Arc::new(w);
        let (texts, keys) = job(2, "same");
        let first = {
            let (w, texts, keys) = (w.clone(), texts.clone(), keys.clone());
            std::thread::spawn(move || w.detect(texts, keys, Duration::from_secs(5)))
        };
        std::thread::sleep(Duration::from_millis(20));
        assert!(w.detect(texts, keys, Duration::from_secs(5)).is_ok());
        assert!(first.join().unwrap().is_ok());
        assert_eq!(det.calls.load(Ordering::SeqCst), 1);
    }
}
