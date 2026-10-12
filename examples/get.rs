//! Fetch a URL with the blocking client and print the response.
//!
//! ```sh
//! cargo run --example get -- http://127.0.0.1:8080/
//! ```

fn main() -> Result<(), http_net::blocking::Error> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8080/".into());
    let resp = http_net::blocking::get(&url)?;
    println!("status: {}", resp.status());
    for (name, value) in resp.headers() {
        println!("{name}: {}", String::from_utf8_lossy(value));
    }
    println!();
    println!("{}", String::from_utf8_lossy(resp.body()));
    Ok(())
}
