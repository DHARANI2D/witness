# Live environment: HotelReservation via docker-compose

This runs AIOpsLab's actual DeathStarBench HotelReservation application
(the same container images AIOpsLab's own orchestrator deploys via
`kubectl apply -f hotelReservation/kubernetes`) as plain Docker
containers, wired to the real WITNESS gate through the real AIOpsLab
`TaskActions.exec_shell`/`ResponseParser` classes (see `../adapters/`).

## Why docker-compose, not kind

The straightforward path would have been a `kind` Kubernetes cluster,
matching AIOpsLab's own setup exactly. That was attempted first and
diagnosed in detail:

1. `docker`, `kind`, `kubectl`, and `helm` all install and run fine in
   this sandbox (Docker itself works — confirmed with `docker run
   hello-world`).
2. `kind create cluster` initially failed with every static pod
   (`kube-apiserver`, `etcd`, ...) stuck in
   `WARN: cgroupns not enabled! Please use cgroup v2, or cgroup v1 with
   cgroupns enabled.` — a real, fixable bug: this sandbox's Docker
   daemon defaults to `cgroupns-mode: host` on its cgroup v1 host.
   Setting `"default-cgroupns-mode": "private"` in
   `/etc/docker/daemon.json` and restarting the daemon fixed this;
   systemd then booted cleanly inside the kind node
   (`systemctl is-system-running` → `running`).
3. With that fixed, cluster creation still failed, now one level
   deeper: every pod sandbox failed with `runc create failed: unable to
   start container process: can't get final child's PID from pipe:
   EOF`. This was investigated systematically, not assumed: PID/mount/
   cgroup namespace limits were checked and are not the bottleneck
   (`/proc/sys/user/max_*_namespaces` = 64313; a manual `unshare --pid
   --mount --uts --ipc --net --fork --mount-proc` at the *same* nesting
   depth inside the kind node succeeds). `dmesg` showed no LSM/seccomp
   denial after the failure. The most consistent explanation is a
   nesting-depth limit in this Firecracker-microVM sandbox specific to
   the full OCI container-create sequence (cgroup delegation + seccomp
   + pivot_root together, not any single primitive) at the 4th level of
   container nesting (host → sandbox → kind node → pod sandbox) — a
   restriction enforced above the Docker layer this session controls,
   so it can't be fixed from inside it.

Given that, this environment runs the exact same container images
directly under Docker instead of Kubernetes: still real, live,
attackable and defensible infrastructure, just without `kubectl` in the
loop. If you're running this on a host without that nesting
restriction, `scripts/setup_aiopslab_dev.sh` plus a normal `kind create
cluster` should work unmodified (with the `cgroupns-mode` fix above, if
you hit the same first symptom).

## Bringing it up

```bash
cd live_env
docker compose up -d
# services register with Consul over the next few seconds; verify with:
curl "http://localhost:5000/hotels?inDate=2026-10-01&outDate=2026-10-02&lat=37.7749&lon=-122.4194"
```

Service names in `docker-compose.yml` match the k8s Service names in
`aiopslab-applications/hotelReservation/kubernetes` exactly (verified
against those manifests, not guessed), so the app's own baked-in
`config.json` — which points at hostnames like `consul`, `mongodb-rate`,
`memcached-reserve` — resolves correctly over Compose's default network
without touching the images.

`mongodb-rate` and `mongodb-geo` run with `--auth` and the exact
`k8s-rate-mongo.sh`/`k8s-geo-mongo.sh` init scripts AIOpsLab itself uses
(copied into `mongo-init/`, mounted at `/docker-entrypoint-initdb.d`)
— those two services are AIOpsLab's real `auth_miss_mongodb` fault
target, and their app code has the `admin`/`admin` credentials
hardcoded (`cmd/rate/db.go`, `cmd/geo/db.go`), which only works if the
init script has run.

## What's real here

- 18 containers, real Go/gRPC microservices, real MongoDB/Consul/Jaeger,
  answering real HTTP requests with real hotel data.
- Real telemetry (`../adapters/live_docker_telemetry.py`): `docker
  stats` and a direct `cpuacct.usage` cgroup read via `docker exec` are
  two genuinely independent measurement code paths, giving the
  two-witness rule real class-diverse corroboration to work with — not
  two calls to the same API.
- Real faults: `docker exec <container> sh -c "yes > /dev/null &"` (x4)
  produces genuine ~380-400% CPU saturation on a 4-core box, observed
  identically by both telemetry paths.
- Real remediation: `docker restart <container>` through the real,
  unmodified `TaskActions.exec_shell`, gated by WITNESS exactly as it
  would gate a `kubectl`-based remediation.

## Local model (Ollama)

`bootstrap_local_env.sh` (below) also brings up a self-hosted
`ollama/ollama` container loaded with a genuinely free, locally-run LLM
— no API key, no cloud account, anywhere. Neither `ollama.com`'s own
registry nor `huggingface.co` are reachable from this environment's
network policy, so the model comes from Docker Hub's `ai/` namespace
(Docker Model Runner) instead, which mirrors small instruct models as
plain OCI artifacts reachable anywhere `docker pull` already works.

`fetch_local_model.sh` does the actual fetch: it gets a bearer token
from Docker's auth endpoint, fetches the image manifest, extracts the
GGUF layer's digest, downloads that blob directly (this is necessary
because `docker pull` alone doesn't expose a runnable model file — the
image's content type is `model`, not `container`, so it has no root
filesystem to `docker cp` out of), and verifies the GGUF magic bytes
before saving it to `models/` (gitignored, ~1GB, not committed).
Default: `ai/smollm2:1.7b-q4_K_M` (SmolLM2-1.7B-Instruct). Browse other
options at https://hub.docker.com/u/ai — each tag's page names the
underlying GGUF and its original source model.

```bash
./fetch_local_model.sh                 # or: ./fetch_local_model.sh ai/<other-model> <tag>
docker run -d --name ollama -p 11434:11434 ollama/ollama:latest
docker cp models/SmolLM2-1.7B-Instruct-Q4_K_M.gguf ollama:/models/smollm2.gguf
docker exec ollama sh -c 'printf "FROM /models/smollm2.gguf\nPARAMETER temperature 0.2\nPARAMETER num_ctx 4096\n" > /tmp/Modelfile'
docker exec ollama ollama create witness-agent -f /tmp/Modelfile
curl http://localhost:11434/api/version   # confirm the server is up
```

`../adapters/ollama_agent.py` is the client used by
`../scripts/pilot_trial_matrix_ollama.py`: it sends each incident
description to `witness-agent` at `/api/chat`, retries up to 3 times
with a corrective format reminder if the reply doesn't parse, and
always parses the raw completion through AIOpsLab's own real
`ResponseParser` — the same class the gated `exec_shell` hook uses —
so whatever the model actually writes is exactly what gets graded, no
simplified stand-in.

## Results

See `results/pilot_trial_results.json` (Claude Sonnet 5 as the
reasoning agent) and `results/pilot_trial_results_ollama.json`
(SmolLM2-1.7B via Ollama, the genuinely independent measurement) for
the raw per-trial output, and the root README's
[Table 1 section](../README.md#table-1--real-measurements-honestly-scoped)
for the summarized numbers and their honest scope (small-N, not the
paper's 180-trial GPT-4o/GPT-4.1 benchmark).

Reproduce with:

```bash
cd ..
./live_env/bootstrap_local_env.sh                 # idempotent: dockerd, Ollama, the app
PYTHONPATH=. python3 scripts/pilot_trial_matrix.py
PYTHONPATH=. python3 scripts/pilot_trial_matrix_ollama.py
PYTHONPATH=. python3 scripts/benchmark_latency.py --trials 3000
```

## Tearing down

```bash
cd live_env
docker compose down -v
```
