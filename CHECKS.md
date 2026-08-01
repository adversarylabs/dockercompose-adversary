# Checks — what dockercompose detects

This file is the **public audit list** of detectors for the **dockercompose** adversary. High-confidence Compose file defects with file:line evidence — privilege escapes, exposed data planes, and mutable supply chain in `compose.yaml` / `docker-compose.yml`.

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** `compose.yaml`, `compose.yml`, `docker-compose.yml`, `docker-compose.*.yml` (override/profile files included). Dockerfile content referenced by `build:` is owned by `container/dockerfile`.

**Precision stance:** Compose files are frequently dev-only — severity language must not assume production. Privilege and socket findings fire regardless (dev laptops are also compromise targets and dev compose files graduate to prod constantly). Port-exposure findings gate on sensitive ports, mirroring `terraform.public-ingress`.

Public grounding: Docker Engine security docs (privileged, capabilities, docker.sock), Compose file reference, and the long record of internet-exposed dev databases (open Redis/Mongo scans) traced to default `0.0.0.0` port publishing.

---

## Critical

### `docker-compose.privileged`

| | |
| --- | --- |
| **What** | Service runs with `privileged: true` |
| **Why** | Disables essentially all container isolation; container compromise becomes host compromise |
| **Looks for** | `privileged: true` on any service |
| **Stays quiet when** | Absent/false. Known DinD-style services still fire, with remediation pointing at rootless alternatives |
| **Public examples** | Docker Engine security docs; container-escape writeups starting from privileged services |
| **Remediation** | Remove privileged mode and add only required capabilities via `cap_add` |

### `docker-compose.docker-sock-mount`

| | |
| --- | --- |
| **What** | Service mounts the Docker socket |
| **Why** | `/var/run/docker.sock` is root-equivalent control of the host's Docker daemon — same blast radius as privileged |
| **Looks for** | `volumes:` entries containing `/var/run/docker.sock` (rw or ro — the API is what matters, not the file mode) |
| **Stays quiet when** | No socket mounts. Socket-proxy sidecars (tecnativa/docker-socket-proxy-style) downgrade to high with a note, not silence |
| **Public examples** | Classic docker.sock escape literature; Traefik/portainer setups copied without understanding |
| **Remediation** | Use a filtered socket proxy or the provider's API with scoped credentials; never the raw socket in app services |

---

## High

### `docker-compose.host-namespace`

| | |
| --- | --- |
| **What** | Service shares host namespaces (`network_mode: host`, `pid: host`, `ipc: host`) |
| **Why** | Removes network/process isolation; host ports and processes become visible and bindable |
| **Looks for** | `network_mode: host`, `pid: host`, `ipc: host`, `userns_mode: host` |
| **Stays quiet when** | Isolated defaults; documented node-agent/monitoring services still fire at high with a targeted remediation |
| **Public examples** | Docker run reference on namespace flags; monitoring-agent tutorials that over-share |
| **Remediation** | Use isolated networks and namespaces; publish specific ports instead of host networking |

### `docker-compose.dangerous-capabilities`

| | |
| --- | --- |
| **What** | `cap_add` grants `SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, or `ALL` |
| **Why** | These capabilities approach privileged mode; SYS_ADMIN in particular is a documented escape vector |
| **Looks for** | `cap_add:` containing those values |
| **Stays quiet when** | Benign caps only (`NET_BIND_SERVICE`, `CHOWN`); `cap_drop: [ALL]` with a minimal add-back list |
| **Public examples** | Linux capabilities man page; capability-based breakout writeups |
| **Remediation** | Drop all, add back the minimum; question any service that "needs" SYS_ADMIN |

### `docker-compose.security-opt-disabled`

| | |
| --- | --- |
| **What** | Security profiles explicitly disabled |
| **Why** | `seccomp:unconfined` / `apparmor:unconfined` / `label:disable` / `no-new-privileges:false` silently remove the default hardening layer |
| **Looks for** | `security_opt:` entries disabling seccomp/AppArmor/SELinux labels |
| **Stays quiet when** | Custom *tightened* profiles referenced by path; defaults untouched |
| **Public examples** | Docker seccomp docs — default profile blocks dozens of syscalls used in escapes |
| **Remediation** | Keep default profiles; if one syscall is needed, ship a custom profile allowing exactly that |

### `docker-compose.sensitive-port-exposed`

| | |
| --- | --- |
| **What** | Data-plane/admin port published without a host-IP restriction |
| **Why** | Compose publishes on `0.0.0.0` by default — `"5432:5432"` on a laptop or VM is an internet-/LAN-exposed database with default credentials. Open Redis/Mongo instances found this way are a recurring breach class |
| **Looks for** | `ports:` publishing sensitive ports (5432, 3306, 6379, 27017, 9200, 11211, 2375, 5601, 15672…) without a loopback bind prefix |
| **Stays quiet when** | Bound to loopback (`"127.0.0.1:5432:5432"`); `expose:` (container-network only); ports 80/443 for intentional public HTTP |
| **Public examples** | Shodan-visible dev databases; Compose port-binding docs |
| **Remediation** | Bind to `127.0.0.1:` for local dev; use `expose:` for inter-service traffic |

### `docker-compose.inline-secret-env`

| | |
| --- | --- |
| **What** | Credential literals in `environment:` |
| **Why** | Compose files are committed; `POSTGRES_PASSWORD: hunter2` is a committed secret with extra YAML |
| **Looks for** | `environment:` keys matching `PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL` with literal, non-placeholder values (entropy/length gate) — compose-context detection; generic pattern scanning stays with `security/secrets` |
| **Stays quiet when** | `${VAR}` interpolation, `env_file:` references, Compose `secrets:` blocks, obvious dev placeholders (`changeme`, `example`) — dev placeholders downgrade to low, not silent, when the service is also port-exposed |
| **Public examples** | Endless committed compose files with real credentials; Compose secrets docs as contrast |
| **Remediation** | Use `${VAR}` from an uncommitted `.env`, `env_file`, or Compose `secrets:` |

---

## Medium

### `docker-compose.mutable-image`

| | |
| --- | --- |
| **What** | Service image uses `:latest` or no tag |
| **Why** | Deploys become non-reproducible; tag moves are a supply-chain vector |
| **Looks for** | `image:` values with `:latest` or no tag and no digest |
| **Stays quiet when** | Any explicit version tag or `@sha256:` digest (recommend digests, don't flag versioned tags); `build:`-only services with no `image:` pull |
| **Public examples** | Same class as `kubernetes.mutable-image` / `dockerfile.from.latest` |
| **Remediation** | Pin deployed images by version tag at minimum, digest for production |

---

## Out of scope (owned elsewhere)

| Concern | Owner |
| --- | --- |
| Dockerfile content behind `build:` | `container/dockerfile` |
| Kubernetes manifests | `kubernetes` |
| Generic secret literals in other file types | `security/secrets` |
| CI pipelines invoking compose | `ci/github-actions` / `ci/depot` / `gitlab-ci` |
