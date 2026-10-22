//! The head passport: a reader parses pipelined requests with the stateless
//! parser into a stack array of spans and copies each head into a pooled
//! passport's vectors. A worker thread rebuilds the view with
//! `OwnedRequestHead::from_parts`, which checks the copy before trusting it,
//! reads the head, and returns the vectors to the pool, so a warm pool
//! copies heads without allocating.
//!
//! ```sh
//! cargo run --example passport
//! ```

use std::sync::mpsc;
use std::thread;

use http_net::{
    FieldSpan, HeadFacts, HttpError, Limits, OwnedRequestHead, Parsed, parse_request_head,
};

/// What crosses the thread boundary: plain bytes, plain spans, plain facts.
struct Passport {
    bytes: Vec<u8>,
    fields: Vec<FieldSpan>,
    facts: Option<HeadFacts>,
}

impl Passport {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(4096),
            fields: Vec::with_capacity(64),
            facts: None,
        }
    }
}

fn main() -> Result<(), HttpError> {
    let input: &[u8] = b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n\
POST /b HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nX-Trace: 7\r\n\r\n\
GET /c HTTP/1.1\r\nHost: exam";

    // Two passports circulate: reader -> worker -> pool -> reader.
    let (to_worker, worker_in) = mpsc::channel::<Passport>();
    let (to_pool, pool) = mpsc::channel::<Passport>();
    for _ in 0..2 {
        to_pool
            .send(Passport::new())
            .map_err(|_| HttpError::InvalidState("pool"))?;
    }

    let worker = thread::spawn(move || -> Result<(), HttpError> {
        for passport in worker_in {
            let facts = passport
                .facts
                .ok_or(HttpError::InvalidState("empty passport"))?;
            let owned = OwnedRequestHead::from_parts(passport.bytes, passport.fields, facts)?;
            let head = owned.view();
            println!(
                "worker: {} {} host={} fields={}",
                head.method_str(),
                head.target(),
                head.host().unwrap_or("-"),
                head.raw().fields().len(),
            );
            // Wipe and return the passport; the vectors keep their capacity.
            let (mut bytes, mut fields, _) = owned.into_parts();
            bytes.clear();
            fields.clear();
            let _ = to_pool.send(Passport {
                bytes,
                fields,
                facts: None,
            });
        }
        Ok(())
    });

    let limits = Limits::default();
    let mut slots = [FieldSpan::default(); 16];
    let mut rest = input;
    loop {
        match parse_request_head(rest, &limits, &mut slots)? {
            Parsed::Complete { head, len } => {
                let view = head.view();
                println!(
                    "reader: {} {} ({len} bytes)",
                    view.method_str(),
                    view.target()
                );
                let Ok(mut passport) = pool.recv() else { break };
                passport.facts = Some(view.copy_into(&mut passport.bytes, &mut passport.fields)?);
                if to_worker.send(passport).is_err() {
                    break;
                }
                // No head here has a body, so the next head starts at `len`.
                rest = &rest[len..];
            }
            Parsed::Partial => {
                println!("reader: {} bytes wait for more input", rest.len());
                break;
            }
            _ => break,
        }
    }
    drop(to_worker);
    worker.join().unwrap_or(Ok(()))
}
