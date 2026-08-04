# container/docker-compose — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `dockercompose`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** docker-compose

## Mission

Review Compose services for privilege, host access, and image reproducibility.

## In scope (fair miss if humans raised it and we did not)

- Privileged services, host mounts
- Mutable images
- Dangerous network/host access in compose

## Out of scope (not a miss for this adversary)

- Single Dockerfile deep review
- K8s manifests

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
