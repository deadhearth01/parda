//! The ML tier runs on its own thread so a slow or stuck model can be timed
//! out. Results that arrive after the caller gave up still land in the ML
//! cache, so the next request with the same text is fast.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{RecvTimeoutError, Sender};
use parda_core::{Detection, MlDetector};

use crate::cache::{DetCache, Key};

/// Texts per `detect_batch` call; bounds peak memory of one inference.
const BATCH: usize = 8;

type Reply = anyhow::Result<Vec<Vec<Detection>>>;

struct Job {
    texts: Vec<String>,
    keys: Vec<Key>,
    reply: Sender<Reply>,
}

pub(crate) struct MlWorker {
    tx: Sender<Job>,
    name: String,
}

impl MlWorker {
    pub(crate) fn spawn(det: Arc<dyn MlDetector>, cache: Arc<DetCache>) -> std::io::Result<Self> {
        let (tx, rx) = crossbeam_channel::unbounded::<Job>();
        let name = det.name().to_string();
        std::thread::Builder::new()
            .name("parda-ml".into())
            .spawn(move || {
                for job in rx {
                    let res = run(det.as_ref(), &job.texts);
                    if let Ok(dets) = &res {
                        for (k, d) in job.keys.iter().zip(dets) {
                            cache.put(*k, Arc::new(d.clone()));
                        }
                    }
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
        self.tx
            .send(Job { texts, keys, reply })
            .map_err(|_| "ML worker stopped".to_string())?;
        match rx.recv_timeout(timeout) {
            Ok(Ok(d)) => Ok(d),
            Ok(Err(e)) => Err(format!("ML detector failed: {e:#}")),
            Err(RecvTimeoutError::Timeout) => Err(format!(
                "ML detector timed out after {} ms",
                timeout.as_millis()
            )),
            Err(RecvTimeoutError::Disconnected) => Err("ML worker stopped".to_string()),
        }
    }
}

fn run(det: &dyn MlDetector, texts: &[String]) -> Reply {
    let mut out = Vec::with_capacity(texts.len());
    for chunk in texts.chunks(BATCH) {
        let refs: Vec<&str> = chunk.iter().map(String::as_str).collect();
        let got = catch_unwind(AssertUnwindSafe(|| det.detect_batch(&refs)))
            .map_err(|_| anyhow::anyhow!("ML detector panicked"))??;
        if got.len() != refs.len() {
            anyhow::bail!(
                "ML detector returned {} results for {} inputs",
                got.len(),
                refs.len()
            );
        }
        out.extend(got);
    }
    Ok(out)
}
