# http-net in the HTTP Garden

This directory adds http-net as an origin server in the
[HTTP Garden](https://github.com/narfindustries/http-garden), a set of HTTP
servers and proxies in containers plus tools that send the same bytes to all
of them and compare how each one understood the request. A disagreement
between two parsers on the same bytes is what request smuggling is built on.

Garden runs need Docker and tens of gigabytes of images, so they happen only
in a manually triggered GitHub Actions job (decision D-58 in `dev/PLAN.md`),
never on a developer machine. Nothing here is part of the published crate:
`garden/` is in the root `Cargo.toml` `exclude` list, and the root crate does
not depend on it.

## What is here

| File | Purpose |
|---|---|
| `src/lib.rs`, `src/main.rs` | The origin: `std::net` with one thread per connection, each driving the sans-IO `ServerConn`. Every request the parser accepts gets `200 OK` and a JSON body in the format all Garden origins use (method, version, target, each field, and the decoded body, each base64-encoded). A request the parser refuses gets the response `Response::from_error` builds, and the connection closes. |
| `tests/echo.rs` | Pins the echo format byte for byte over a localhost socket. |
| `Dockerfile` | The image, on the Garden's `http-garden-soil` base. It builds the origin in debug mode so overflow checks and debug assertions stay on. |
| `compose.yml` | The `http_net` service, merged into the Garden's `docker-compose.yml`. |
| `quirks.yml` | The fallback `http_net` entry for the Garden's `quirks.yml` (no quirks). |
| `register.py` | Merges the two files above into a Garden checkout and copies in the driver. |
| `http_net_grid.py` | The driver: the REPL's `fanout` and `grid` from the command line, over a list of seeds. |
| `seeds.txt` | Seeds of our own, run after the payloads documented in the Garden's `TROPHIES.md`. |

## Running it

From a checkout with the GitHub CLI signed in:

```sh
gh workflow run garden.yml
```

That uses the defaults: the Garden at a pinned commit, `http_net` compared
with `hyper`, `nginx`, `h2o`, and `gunicorn`, each seed also sent through
`haproxy`, and 500 random mutations. Any of them can be changed:

```sh
gh workflow run garden.yml \
  -f origins="hyper nginx" \
  -f transducers="" \
  -f mutations=2000 \
  -f rng_seed=7 \
  -f garden_ref=<full commit SHA of narfindustries/http-garden>
```

`origins` and `transducers` take Garden service names from its
`docker-compose.yml`. Each one is an image built from source, so every name
adds build time; a run with the defaults takes roughly half an hour to an
hour, most of it building. To run a branch other than the default, add
`--ref <branch>`. Watch it with `gh run watch`, and fetch the results with
`gh run download <run id>`.

To move to a newer Garden, pick a commit from its `main` branch, run the job
with `garden_ref` set to it, and once it runs cleanly, update the default in
`.github/workflows/garden.yml`.

## What the job does

1. Checks out http-net and the Garden at `garden_ref`.
2. Stages `images/http_net` in the Garden checkout: this `Dockerfile` and a
   `git archive` of the http-net commit being run, then runs `register.py`.
3. Builds the Garden's base image and the requested images with the Garden's
   own `garden.sh build`, and starts them with `docker compose up -d`.
4. Runs the Garden's `probe_quirks.py` on `http_net` and records what it finds
   in `quirks.yml`, as the Garden does for every other server. If probing
   fails, the fallback entry stays and the job notes it.
5. Runs `http_net_grid.py`. For each seed it sends the bytes to every origin
   and compares each pair the way the REPL's `grid` does, including the
   Garden's allowances for each server's known quirks. It then sends the seed
   through each transducer and compares what the origins make of the
   transducer's output. Last, it runs the requested number of mutations of the
   seeds with the Garden's own mutators, from a fixed RNG seed, so a run can be
   repeated exactly.
6. Saves the logs of every container, and calls out any panic in `http_net`.

The job fails only when the harness cannot run: an image does not build, a
service does not start or answer within five minutes, or `http_net` does not
answer a plain `GET` in the Garden's format. Discrepancies never fail it.
They are findings that need a person to decide whether http-net is wrong, the
other server is wrong, or both are within what the RFCs allow.

## Reading the results

The job summary page shows `summary.md`. The artifact `garden-results-<run id>`
holds:

| File | Contents |
|---|---|
| `summary.md` | Every case in which `http_net` disagrees with at least one origin, in two tables. |
| `results.json` | Every case in which any two origins disagree: the payload, what each origin reported, and each disagreeing pair. |
| `grids.txt` | The REPL-style grid for each case in `summary.md`. |
| `http_net.log`, `compose.log` | Container output. A panic in `http_net` shows up here. |
| `http_net_quirks.yml` | What `probe_quirks.py` found for `http_net`. |
| `docker-compose.yml`, `quirks.yml` | The Garden configuration the run used. |

The first table in `summary.md` lists cases where `http_net` and `hyper`
disagree. Triage those first: the 0.7 hypothesis in `dev/PLAN.md` is that the
Garden finds no discrepancy class in http-net that hyper does not also have.
The second table lists cases where `http_net` agrees with `hyper` and differs
from some other origin, which more often points at the other server.

Each disagreement has a category, from the Garden's own classifier:

- `type_discrepancy`: one origin accepted the bytes and the other rejected
  them. When `http_net` is the one rejecting, check the error against RFC
  9112; http-net is meant to be strict, so many of these are expected.
- `request_discrepancy`: both accepted, but read a different method, target,
  field, or body. These matter most, since a proxy and an origin reading the
  same bytes differently is the core of smuggling.
- `stream_discrepancy`: a different number of messages, or no answer at all.
  Look for pipelining and framing (where one request ends and the next
  begins).
- `invalid`: an origin accepted a request whose fields hold bytes RFC 9110
  forbids (CR, LF, or NUL in a value, or a non-token name or method). If
  `http_net` is one side of such a pair, check which side reported the bad
  bytes in `results.json`.

Two origins that both reject the bytes, even with different status codes,
count as agreeing, as they do in the Garden.

The `Stable` column says whether the same disagreement came back when the
case was sent a second time. The Garden reads each answer until the socket
has been quiet for 50 ms, so a slow container can turn a correct answer into
a missing one. Rerun anything marked `no` before spending time on it.

To reproduce a case by hand, copy its payload from `results.json` into the
Garden's REPL on a machine with Docker:

```text
garden> payload '<payload>' | fanout http_net hyper | grid
```

## Running the origin outside the Garden

The origin is an ordinary program, so its echo can be checked with curl:

```sh
cd garden
cargo test
cargo run -- 127.0.0.1:8080
curl -s http://127.0.0.1:8080/x -d hello
```

The response body is the JSON the Garden parses, with each value
base64-encoded.
