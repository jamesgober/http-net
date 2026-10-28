# The http-net origin for the HTTP Garden. Build context: the Garden's
# images/http_net, holding this file and http-net/ (a `git archive` of the
# http-net commit under test, staged by .github/workflows/garden.yml).
FROM http-garden-soil:latest

ARG RUST_TOOLCHAIN=stable
RUN apt -y update \
 && apt -y install --no-install-recommends curl \
 && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN" \
 && rm -rf /var/lib/apt/lists/*

COPY http-net /app/http-net

# A debug build: overflow checks and debug assertions stay on, so a fault
# shows up as a panic in the container log instead of a quiet wrong answer.
# The soil image's C sanitizer flags do not apply to Rust code.
RUN cd /app/http-net/garden \
 && . ~/.cargo/env \
 && unset CC CXX CFLAGS CXXFLAGS LDFLAGS \
 && cargo build --bin http-net-garden \
 && cp target/debug/http-net-garden /usr/local/bin/http-net-garden

ENV RUST_BACKTRACE=1
CMD ["/usr/local/bin/http-net-garden", "0.0.0.0:80"]
