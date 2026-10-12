//! Load test: many concurrent Anthropic-style requests through the proxy to
//! the echo mock. Checks that every answer carries the real values back and
//! reports throughput and end-to-end latency percentiles.

use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use serde_json::json;
use tokio::sync::Semaphore;

use crate::latency::percentile;

#[derive(Debug, Serialize)]
pub struct LoadReport {
    pub requests: usize,
    pub concurrency: usize,
    pub stream: bool,
    pub seconds: f64,
    pub throughput_rps: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    /// Non-2xx answers or transport failures.
    pub errors: usize,
    /// Answers that did not carry the real values back.
    pub leaks: usize,
}

const NAMES: &[&str] = &[
    "Venkatesh Iyer",
    "Priya Sharma",
    "Siobhan O'Brien",
    "Rahul Verma",
    "Anjali Nair",
    "Mohammed Faizal Shaikh",
    "Gurpreet Kaur",
    "Klaus Weber",
    "Ananya Chatterjee",
    "Arjun Reddy",
];

fn prompt(i: usize) -> (String, String) {
    let name = NAMES[i % NAMES.len()];
    let email = format!("user{}.test@gmail.com", i % 97);
    // Half the requests repeat earlier text (agents resend history).
    let tail = if i % 2 == 0 {
        String::new()
    } else {
        format!(" Ticket #{i}.")
    };
    (
        format!("Please write to {name} at {email} about the refund.{tail}"),
        email,
    )
}

pub async fn run(
    url: &str,
    concurrency: usize,
    requests: usize,
    stream: bool,
) -> anyhow::Result<LoadReport> {
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(concurrency)
        .build()?;
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(requests);
    for i in 0..requests {
        let permit = sem.clone().acquire_owned().await?;
        let client = client.clone();
        let url = format!("{}/v1/messages", url.trim_end_matches('/'));
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let (text, email) = prompt(i);
            let body = json!({"model": "mock", "max_tokens": 64, "stream": stream,
                              "messages": [{"role": "user", "content": text}]});
            let t = Instant::now();
            let res = client
                .post(&url)
                .header("x-api-key", "load-test")
                .header("anthropic-version", "2023-06-01")
                .json(&body)
                .send()
                .await;
            let (ok, leak) = match res {
                Ok(r) if r.status().is_success() => {
                    let body = r.text().await.unwrap_or_default();
                    // The echo must come back with the real e-mail restored.
                    (true, !body.contains(&email))
                }
                _ => (false, false),
            };
            (t.elapsed().as_secs_f64() * 1000.0, ok, leak)
        }));
    }
    let mut ms = Vec::with_capacity(requests);
    let (mut errors, mut leaks) = (0, 0);
    for t in tasks {
        let (m, ok, leak) = t.await?;
        ms.push(m);
        errors += usize::from(!ok);
        leaks += usize::from(leak);
    }
    let seconds = started.elapsed().as_secs_f64();
    ms.sort_by(f64::total_cmp);
    Ok(LoadReport {
        requests,
        concurrency,
        stream,
        seconds,
        throughput_rps: requests as f64 / seconds.max(1e-9),
        p50_ms: percentile(&ms, 0.5),
        p95_ms: percentile(&ms, 0.95),
        p99_ms: percentile(&ms, 0.99),
        max_ms: ms.last().copied().unwrap_or(0.0),
        errors,
        leaks,
    })
}
