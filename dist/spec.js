export const spec = {
    "id": "docker-compose",
    "displayName": "Docker Compose",
    "description": "Reviews Compose services for privilege, host access, and image reproducibility.",
    "files": [
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
        "**/compose.yml",
        "**/docker-compose.yml"
    ],
    "rules": [
        {
            "id": "docker-compose.privileged",
            "title": "Compose service runs privileged",
            "summary": "Compose service runs privileged",
            "category": "security",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Compose service runs privileged weakens an important security boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Remove privileged mode and add only required capabilities.",
            "complexity": "small",
            "tags": [
                "security",
                "privileged"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "compose.yml",
                    "compose.yaml",
                    "docker-compose.yml",
                    "docker-compose.yaml",
                    "**/compose.yml",
                    "**/docker-compose.yml"
                ],
                "pattern": {
                    "pattern": "privileged:\\s*true",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "docker-compose.host-namespace",
            "title": "Compose service joins a host namespace",
            "summary": "Compose service joins a host namespace",
            "category": "security",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Compose service joins a host namespace weakens an important security boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Use isolated networks and PID/IPC namespaces.",
            "complexity": "small",
            "tags": [
                "security",
                "host-namespace"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "compose.yml",
                    "compose.yaml",
                    "docker-compose.yml",
                    "docker-compose.yaml",
                    "**/compose.yml",
                    "**/docker-compose.yml"
                ],
                "pattern": {
                    "pattern": "(?:network_mode|pid|ipc):\\s*[\"']?host",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "docker-compose.mutable-image",
            "title": "Compose service uses a mutable image",
            "summary": "Compose service uses a mutable image",
            "category": "supply-chain",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Compose service uses a mutable image weakens an important supply-chain boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Pin deployed images by digest.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "mutable-image"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "compose.yml",
                    "compose.yaml",
                    "docker-compose.yml",
                    "docker-compose.yaml",
                    "**/compose.yml",
                    "**/docker-compose.yml"
                ],
                "pattern": {
                    "pattern": "image:\\s*[^\\s]+:(?:latest|main|edge)\\b",
                    "flags": "i"
                },
                "requires": []
            }
        }
    ]
};
