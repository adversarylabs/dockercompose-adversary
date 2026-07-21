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

## Automatic detection

`adversary auto` selects the docker-compose adversary when changes include `compose.yml` or `compose.yaml`, plus the other domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not select it.
