# Docker Compose adversary

Reviews Compose services for privilege, host access, and image reproducibility.

## Checks

- **Compose service runs privileged:** Remove privileged mode and add only required capabilities.
- **Compose service joins a host namespace:** Use isolated networks and PID/IPC namespaces.
- **Compose service uses a mutable image:** Pin deployed images by digest.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```
