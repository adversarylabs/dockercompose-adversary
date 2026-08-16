# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `docker-compose.dangerous-capabilities` | High | `cap_add` grants `SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, or `ALL` |
| `docker-compose.docker-sock-mount` | Critical | Service mounts the Docker socket |
| `docker-compose.host-namespace` | High | Service shares host namespaces (`network_mode: host`, `pid: host`, `ipc: host`) |
| `docker-compose.inline-secret-env` | High | Credential literals in `environment:` |
| `docker-compose.mutable-image` | Medium | Service image uses `:latest` or no tag |
| `docker-compose.privileged` | Critical | Service runs with `privileged: true` |
| `docker-compose.security-opt-disabled` | High | Security profiles explicitly disabled |
| `docker-compose.sensitive-port-exposed` | High | Data-plane/admin port published without a host-IP restriction |
| `docker-compose.writable-git-bind` | Medium | A service bind-mounts the host repository's `.git` directory with write access |
