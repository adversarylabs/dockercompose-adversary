import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

const COMPOSE_FILES = [
  "compose.yml",
  "compose.yaml",
  "docker-compose.yml",
  "docker-compose.yaml",
  "**/compose.yml",
  "**/compose.yaml",
  "**/docker-compose.yml",
  "**/docker-compose.yaml",
] as const;

export const spec = {
  "id": "docker-compose",
  "displayName": "Docker Compose",
  "description": "Reviews Compose services for privilege, host access, and image reproducibility.",
  "files": [...COMPOSE_FILES],
  "rules": [
    {
      "id": "docker-compose.privileged",
      "title": "Compose service runs privileged",
      "summary": "Compose service runs privileged",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "privileged: true disables container isolation; compromise becomes host compromise.",
      "impact": "Container escape and full host control from a single service compromise.",
      "recommendation": "Remove privileged mode and add only required capabilities via cap_add.",
      "complexity": "small",
      "tags": ["security", "privileged"],
      "match": {
        "kind": "content",
        "files": [...COMPOSE_FILES],
        "pattern": { "pattern": "privileged:\\s*true", "flags": "i" },
        "requires": []
      }
    },
    {
      "id": "docker-compose.docker-sock-mount",
      "title": "Compose service mounts the Docker socket",
      "summary": "Compose service mounts the Docker socket",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "/var/run/docker.sock is root-equivalent control of the host Docker daemon.",
      "impact": "Any process in the container can create privileged containers and take over the host.",
      "recommendation": "Use a filtered socket proxy or the provider API with scoped credentials; never the raw socket in app services.",
      "complexity": "small",
      "tags": ["security", "docker-sock"],
      "match": {
        "kind": "content",
        "files": [...COMPOSE_FILES],
        "pattern": { "pattern": "/var/run/docker\\.sock", "flags": "i" },
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
      "whyItMatters": "Host network/PID/IPC namespaces remove process and network isolation.",
      "impact": "Host ports and processes become visible and bindable from the container.",
      "recommendation": "Use isolated networks and namespaces; publish specific ports instead of host networking.",
      "complexity": "small",
      "tags": ["security", "host-namespace"],
      "match": {
        "kind": "content",
        "files": [...COMPOSE_FILES],
        "pattern": { "pattern": "(?:network_mode|pid|ipc|userns_mode):\\s*[\"']?host", "flags": "i" },
        "requires": []
      }
    },
    {
      "id": "docker-compose.dangerous-capabilities",
      "title": "Compose service grants dangerous capabilities",
      "summary": "Compose service grants dangerous capabilities",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "SYS_ADMIN, SYS_PTRACE, NET_ADMIN, and ALL approach privileged mode and enable known escapes.",
      "impact": "Capability-based container breakout and host network manipulation.",
      "recommendation": "Drop all capabilities and add back only the minimum required set.",
      "complexity": "small",
      "tags": ["security", "capabilities"],
      "match": {
        "kind": "content",
        "files": [...COMPOSE_FILES],
        "pattern": { "pattern": "cap_add:[\\s\\S]{0,120}(?:SYS_ADMIN|SYS_PTRACE|NET_ADMIN|ALL)\\b", "flags": "i" },
        "requires": []
      }
    },
    {
      "id": "docker-compose.security-opt-disabled",
      "title": "Compose service disables security profiles",
      "summary": "Compose service disables security profiles",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Disabling seccomp, AppArmor, SELinux labels, or no-new-privileges removes default hardening.",
      "impact": "Syscall and LSM protections that block common escape techniques are turned off.",
      "recommendation": "Keep default profiles; ship a custom profile that allows only the required syscalls if needed.",
      "complexity": "small",
      "tags": ["security", "security-opt"],
      "match": {
        "kind": "content",
        "files": [...COMPOSE_FILES],
        "pattern": {
          "pattern": "security_opt:[\\s\\S]{0,160}(?:seccomp[=:]\\s*unconfined|apparmor[=:]\\s*unconfined|label[=:]\\s*disable|no-new-privileges[=:]\\s*false)",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "docker-compose.sensitive-port-exposed",
      "title": "Sensitive port published without host-IP restriction",
      "summary": "Sensitive port published without host-IP restriction",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Compose publishes on 0.0.0.0 by default — data-plane ports become LAN/internet-exposed.",
      "impact": "Open databases, caches, and admin UIs with weak or default credentials.",
      "recommendation": "Bind to 127.0.0.1 for local dev; use expose for inter-service traffic.",
      "complexity": "small",
      "tags": ["security", "ports"],
      "match": {
        "kind": "content",
        "files": [...COMPOSE_FILES],
        "pattern": {
          "pattern": "ports:[\\s\\S]{0,240}[\"'](?!127\\.0\\.0\\.1)[^\"']*\\b(?:5432|3306|6379|27017|9200|11211|2375|5601|15672):",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "docker-compose.inline-secret-env",
      "title": "Credential literal in Compose environment",
      "summary": "Credential literal in Compose environment",
      "category": "secrets",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Compose files are committed; password/token literals become committed secrets.",
      "impact": "Leaked credentials for databases and third-party APIs from repository history.",
      "recommendation": "Use ${VAR} interpolation, env_file, or Compose secrets instead of literals.",
      "complexity": "small",
      "tags": ["secrets", "environment"],
      "match": {
        "kind": "content",
        "files": [...COMPOSE_FILES],
        "pattern": {
          "pattern": "(?:PASSWORD|SECRET|TOKEN|API_KEY|CREDENTIAL)[A-Z0-9_]*:\\s*[\"']?(?!\\$\\{)(?!changeme)(?!example)(?!placeholder)(?!xxx)[^\\s\"'$#]{6,}",
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
      "whyItMatters": "Floating tags make deploys non-reproducible and enable tag-move supply-chain attacks.",
      "impact": "Unexpected image content on redeploy without a lockable pin.",
      "recommendation": "Pin deployed images by version tag at minimum, digest for production.",
      "complexity": "small",
      "tags": ["supply-chain", "mutable-image"],
      "match": {
        "kind": "content",
        "files": [...COMPOSE_FILES],
        "pattern": { "pattern": "image:\\s*[^\\s@]+:(?:latest|main|edge)\\b", "flags": "i" },
        "requires": []
      }
    }
  ]
} as const satisfies AdversarySpec;
