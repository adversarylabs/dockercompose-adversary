# Initial checks

## docker-compose.privileged

- Severity: critical
- Category: security
- Recommendation: Remove privileged mode and add only required capabilities.

## docker-compose.host-namespace

- Severity: high
- Category: security
- Recommendation: Use isolated networks and PID/IPC namespaces.

## docker-compose.mutable-image

- Severity: medium
- Category: supply-chain
- Recommendation: Pin deployed images by digest.

