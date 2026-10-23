# Single-node OSS incidents

This fork adds incident management to the v1.1.2 OSS application on branch
`custom-main`, based on `d16d693ba99bc20621a58b948ecbcad7ec7fa882`.
Alerts opt in through **Creates Incident**. Incidents support Open, Acknowledged,
and Resolved states, P1–P4 severity, title edits, comments, related alert rules,
firing history, and an authenticated activity timeline. Repeated firings preserve
acknowledgment; a firing after resolution creates a new incident.

AI analysis, inferred topology, on-call escalation, external alert ingestion, and
multi-node correlation are outside this implementation. The global Enterprise
build feature stays disabled. Existing Enterprise source directories are stubs;
OSS checks do not verify Enterprise compilation.

## Configuration and storage

| Variable | Default | Meaning |
| --- | --- | --- |
| `ZO_LOCAL_MODE` | `true` | Required; OSS incidents are disabled outside local mode. |
| `ZO_OSS_INCIDENTS_ENABLED` | `true` | Enable the single-node incident service and UI capability. |
| `ZO_OSS_INCIDENTS_GROUPING_FIELDS` | empty | Comma-separated alert-result fields for exact correlation across rules. |
| `ZO_OSS_INCIDENTS_AUTO_RESOLVE_TIMEOUT_SECS` | `0` | Optional inactivity timeout; zero disables it. |

The default grouping key includes organization and alert ID. Explicit grouping
uses canonical field names and nonempty values; any missing, empty, or null value
falls back to alert ID. For example, `service_name,environment` combines rules
only when both result-row fields match. Inactivity resolution means no firings
for the timeout; it does not establish recovery of the monitored service.

Keep SQLite metadata and the existing persistent `/data` volume. Incident data
uses existing tables and requires no new schema marker. Existing GCS object
storage and authentication configuration continue to apply. Alerts that do not
opt in retain their ordinary notification behavior.

Incident creation, a distinct rule joining, and severity changes notify the
deduplicated destinations of related rules. Successful ordinary repeats do not
notify. A failed incident path retains direct-alert fallback. Pending incident
deliveries persist across restarts; partial delivery followed by retry can send
duplicates. Retry bookkeeping uses namespaced internal JSON in
`topology_context`, hidden from the public OSS topology response. Before moving
this database to Enterprise topology support, inspect or convert that metadata.

## Verification status and resources

Local verification was performed on an Apple M4, arm64 macOS, with 16 GB RAM.
At packaging preparation, about 30 GiB disk remained; `target/` occupied 12 GiB,
`web/node_modules/` 873 MiB, and real built `web/dist/` 76 MiB. Builds used two
Cargo jobs, disabled incremental compilation, and zero debug information to fit
these limits. They remain debug-profile builds as required by `AGENTS.md`.

The project pins `nightly-2026-05-20` in `rust-toolchain.toml`; protoc is 21.12
in the existing CI setup. Use `Cargo.lock` with `--locked` and
`web/package-lock.json` with `npm ci`. Existing CI uses Node 24; the local checks
used Node 26.5.0 and npm 11.17.0. The image workflow records the actual selected
Node/npm patch versions and lockfile hashes. The frontend build also fetches
`o2-datasource` content outside npm; this workflow pins it to
`700dcc51f6cb3aff32c5ef1733008456e14d0f38` and saves its fetch metadata.

The implementation handoff records 14 core incident tests, 21 API tests, 450
focused frontend tests, full Rust formatting and workspace Clippy, frontend
formatting, ESLint, type checks, the full web asset build, and a successful debug
application build. The controller's final report records the running-server result.
macOS compact-unwind linker warnings and existing Vite CSS/import/chunk warnings
were observed. These results do not establish a Linux image build or production
acceptance.

**The native Linux image workflow below has not been executed. No image has been
published, and the existing production image must stay unchanged until Linux
packaging and acceptance are validated.** A macOS arm64 executable cannot be
packaged for the confirmed `linux/amd64` VM.

## Native Linux verification and image artifact

`.github/workflows/oss-incidents-image.yml` is manually dispatched and runs on
native `ubuntu-24.04` x86_64. It has read-only repository contents permission,
uses no registry credentials, and saves a Docker image artifact without pushing
an image. Select **Build custom OpenObserve image** and branch `custom-main` in
Actions. A run builds frontend assets once, builds one native OSS debug binary
with embedded assets, then uses
`deploy/build/Dockerfile.pr` to package it. The packaging build explicitly enables
the existing `rust-embed-for-web/always-embed` dependency feature by selecting
both `openobserve` and `web`; otherwise debug mode reads the compile-time asset
directory on disk and a binary-only image loses its UI. No Cargo manifest or
Enterprise feature change is needed. The Docker context contains only
the Dockerfile and `bin/openobserve`. npm and Cargo dependencies are cached;
formatting, linting, type checks, unit tests and test containers are omitted.
The first uncached build can still take time. It never uploads the checkout, Cargo
target directory, or npm dependencies as a Docker context.

The runner must have at least 20 GiB free before dependencies; allow 30 GiB or
more and additional headroom if a run exhausts disk. A larger native x86_64
runner may be needed for this workspace. The workflow stops early below its
disk floor. Its 6 GiB Node heap and two Cargo jobs follow the local resource
limits. No `--release` build is authorized by this handoff.

After approval to push the reviewed branch, the workflow can be dispatched once
GitHub has registered it on the fork's default branch; select the reviewed
feature branch as the run ref. Adding a new workflow only on a feature branch
does not make it available in the default-branch Actions dispatch list. Until
registration is arranged, use the same commands on a disposable native Linux
x86_64 builder without merging application changes. Full history and tags are
required because `src/config/build.rs` obtains application version and revision
from Git. Build outside any checkout containing a production `.env`.

For a native builder, install build-essential, pkg-config, libssl-dev, clang,
cmake, protoc 21.12, Node 24/npm, Docker, and the pinned Rust nightly, then:

```sh
test "$(uname -s)/$(uname -m)" = Linux/x86_64
test ! -e .env
git describe --tags --abbrev=0
export CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export CARGO_INCREMENTAL=0 CARGO_NET_GIT_FETCH_WITH_CLI=true
export NODE_OPTIONS=--max-old-space-size=6144
export DS_CONTENT_REF=700dcc51f6cb3aff32c5ef1733008456e14d0f38
export ZO_DATA_DIR="$(mktemp -d)/"
cd web
npm ci
npm run format:check
npm run lint:ci -- --quiet
npm run type-check:app
npx vitest run src/utils/incidentCapabilities.spec.ts src/components/alerts/steps/AlertSettings.spec.ts src/components/alerts/IncidentDetailDrawer.spec.ts src/composables/shared/useEnterpriseRoutes.spec.ts src/layouts/MainLayout.nav.spec.ts src/plugins/correlation/TelemetryCorrelationDashboard.spec.ts src/services/incidents.spec.ts src/stores/incidents.spec.ts src/lib/core/Navbar/navGroups.spec.ts --maxWorkers=1
npm run build
cd ..
cargo fmt --all -- --check
cargo test -p openobserve-core incidents_oss --lib --locked
cargo test -p openobserve-api-management incidents --lib --locked
cargo clippy --workspace --all-targets -- -W clippy::too_many_lines -W clippy::cognitive_complexity -W clippy::excessive_nesting -D warnings
cargo build --locked -p openobserve -p web --features rust-embed-for-web/always-embed --target x86_64-unknown-linux-gnu
image_context=$(mktemp -d)
mkdir -p "$image_context/bin"
cp target/x86_64-unknown-linux-gnu/debug/openobserve "$image_context/bin/openobserve"
cp deploy/build/Dockerfile.pr "$image_context/Dockerfile"
source_revision=$(git rev-parse HEAD)
image_tag="oss-incidents:amd64-$source_revision"
docker build --platform linux/amd64 --label "org.opencontainers.image.revision=$source_revision" --tag "$image_tag" "$image_context"
docker image inspect --format '{{.Os}}/{{.Architecture}} {{.Id}}' "$image_tag"
```

Run the isolated checks below before exporting an image:

```sh
set -o pipefail
docker save "$image_tag" | gzip > oss-incidents-linux-amd64.tar.gz
sha256sum oss-incidents-linux-amd64.tar.gz > SHA256SUMS
```

The workflow artifact includes this archive, `SHA256SUMS`, `build-metadata.txt`,
`datasource-content.json`, `image-inspect.json`, and container smoke logs. Verify
the checksum before `docker load --input oss-incidents-linux-amd64.tar.gz` on a
disposable amd64 host. Artifact retention is seven days; download and preserve
the reviewed artifact if needed beyond that interval. Record the image ID and
source revision. This is a repeatable procedure, not a byte-for-byte deterministic
build: build timestamps, the Node 24 patch selection, runtime base tag, and apt
packages can change. The saved archive checksum identifies the exact artifact.

## Disposable instance and HTTP smoke

Use local disk storage and a new directory, with no production credentials or
GCS bucket. The following container stays bound to loopback; choose an unused
host port. `image_tag` is the locally loaded amd64 image tag recorded above.

```sh
smoke_data=$(mktemp -d)
export ZO_SMOKE_EMAIL=smoke@example.com
export ZO_SMOKE_PASSWORD
ZO_SMOKE_PASSWORD=$(openssl rand -hex 24)
docker run --detach --name oss-incidents-smoke \
  --publish 127.0.0.1:5088:5080 \
  --mount "type=bind,src=$smoke_data,dst=/data" \
  --env ZO_LOCAL_MODE=true --env ZO_LOCAL_MODE_STORAGE=disk \
  --env ZO_META_STORE=sqlite --env ZO_DATA_DIR=/data/ \
  --env ZO_OSS_INCIDENTS_ENABLED=true \
  --env ZO_OSS_INCIDENTS_AUTO_RESOLVE_TIMEOUT_SECS=0 \
  --env "ZO_ROOT_USER_EMAIL=$ZO_SMOKE_EMAIL" \
  --env "ZO_ROOT_USER_PASSWORD=$ZO_SMOKE_PASSWORD" \
  "$image_tag"
python3 scripts/oss-incidents-smoke.py http://127.0.0.1:5088 --org default
```

The script waits for health, verifies the web HTML and referenced JavaScript
bundle load, checks unauthenticated incident requests return 401,
checks authenticated full config advertises incidents with AI/topology false,
reads list and stats, and verifies invalid pagination/status requests return 400.
It only sends GET requests. It can also target a separately started native debug
binary. Start that binary from a fresh working directory, because a checkout
`.env` overrides process environment; set the same variables plus
`ZO_HTTP_PORT=5088` and an absolute disposable `ZO_DATA_DIR`.

The workflow restarts its empty disposable instance and repeats these HTTP
checks. This verifies startup after restart; incident persistence needs the
populated lifecycle acceptance below.

## Alert lifecycle and acceptance

Use `/web/` on the disposable instance, its root credentials, and a controlled
webhook receiver that records request counts and JSON payloads. Create a webhook
destination with the existing incident payload contract. Use a stream and alert
names reserved for this run, and capture incident IDs and delivery counts after
each step. Avoid overlapping scheduled firings: a realtime alert on individually
ingested matching records gives controlled firings.

1. Confirm **Incidents** and **Creates Incident** are accessible in OSS. The
   incident page must offer overview, activity/comments, and related alerts,
   without AI analysis, service topology, or on-call controls or background calls.
2. Create an enabled realtime log alert with **Creates Incident** on, using a
   condition such as `smoke = true`, and the controlled destination. Ingest one
   matching record. Confirm one Open P3 incident, one firing in its related-alert
   history, and one incident notification. Record its ID. Ingest another matching
   record: the same incident must have two firings with the same single delivery.
   Do not use the destination test or alert-preview controls as proof of actual
   alert evaluation.
3. Acknowledge the incident and ingest a third matching record. Confirm status
   stays Acknowledged, the history has three firings, and no repeat delivery was
   added. The activity timeline must identify the authenticated acknowledgment
   actor. Edit the title, add a comment, and verify both persist with actor events.
4. Set severity P2. Confirm exactly one additional incident notification and a
   severity event. Setting P2 again must not add a severity-change delivery.
5. Resolve, then ingest a fourth matching record. Confirm the original remains
   Resolved and a distinct Open incident appears with one firing and its initial
   notification. With this single-rule/single-destination sequence, expect three
   incident deliveries total: first creation, severity change, second creation.
6. Restart `oss-incidents-smoke` with the same mount. Run the HTTP script again;
   confirm both incident IDs, resolved/active status, title, comment, severity,
   firing histories, and actor events survive in the UI/API.
7. In a separate controlled run, configure grouping fields
   `service_name,environment` and restart. Use two rules with exactly matching
   result-row values. Their firings must join one incident; a distinct rule
   joining notifies all deduplicated related destinations. An absent, null, or
   empty grouping field must fall back to that rule's own incident. Verify the
   same values in a different organization cannot join the first organization's
   incident, and a user without organization access cannot read or mutate it.
8. Make the receiver fail, fire, and restore it. Confirm direct-alert fallback
   and incident retry; stop/restart between failure and retry to check durable
   pending state. Account separately for fallback requests and possible partial
   delivery duplicates. A non-opted-in alert must retain direct notification and
   create no incident. Test configured inactivity resolution separately; leave
   its timeout zero for the deterministic manual lifecycle above.

Repeat relevant checks using an offline disposable copy of existing v1.1.2
SQLite metadata and isolated local object storage. Do not use the live writable
production database or object bucket. Confirm old alerts/authentication remain
usable and metadata requires no reset. A safe prior-image rollback must preserve
the pre-upgrade SQLite backup and prior image digest; do not assume downgrade
safety solely from an unchanged schema marker.

After collecting logs, stop the test container with
`docker stop oss-incidents-smoke`. Keep its disposable data until acceptance is
reviewed. Publication requires the chosen registry/tag, the validated amd64
artifact, explicit approval to publish, and a recorded immutable registry digest.
Only then prepare the deployment image reference and obtain approval to restart
the VM. This handoff does not change the official production image reference.

## Laptop runner

The image workflow now uses `[self-hosted, mac-anang]` with Docker Desktop running. It invokes `bash scripts/build-custom-image.sh`, which builds a Linux amd64 debug binary inside Docker and uploads the same image archive. Docker caches dependencies locally. Keep the laptop awake; the first build on Apple Silicon uses amd64 emulation and may be slow. The earlier native Ubuntu procedure remains a manual alternative.
