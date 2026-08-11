import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "docker-compose";
    readonly displayName: "Docker Compose";
    readonly description: "Reviews Compose services for privilege, host access, and image reproducibility.";
    readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/compose.yaml", "**/docker-compose.yml", "**/docker-compose.yaml"];
    readonly rules: [{
        readonly id: "docker-compose.privileged";
        readonly title: "Compose service runs privileged";
        readonly summary: "Compose service runs privileged";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "privileged: true disables container isolation; compromise becomes host compromise.";
        readonly impact: "Container escape and full host control from a single service compromise.";
        readonly recommendation: "Remove privileged mode and add only required capabilities via cap_add.";
        readonly complexity: "small";
        readonly tags: ["security", "privileged"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/compose.yaml", "**/docker-compose.yml", "**/docker-compose.yaml"];
            readonly pattern: {
                readonly pattern: "privileged:\\s*true";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "docker-compose.docker-sock-mount";
        readonly title: "Compose service mounts the Docker socket";
        readonly summary: "Compose service mounts the Docker socket";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "/var/run/docker.sock is root-equivalent control of the host Docker daemon.";
        readonly impact: "Any process in the container can create privileged containers and take over the host.";
        readonly recommendation: "Use a filtered socket proxy or the provider API with scoped credentials; never the raw socket in app services.";
        readonly complexity: "small";
        readonly tags: ["security", "docker-sock"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/compose.yaml", "**/docker-compose.yml", "**/docker-compose.yaml"];
            readonly pattern: {
                readonly pattern: "/var/run/docker\\.sock";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "docker-compose.host-namespace";
        readonly title: "Compose service joins a host namespace";
        readonly summary: "Compose service joins a host namespace";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Host network/PID/IPC namespaces remove process and network isolation.";
        readonly impact: "Host ports and processes become visible and bindable from the container.";
        readonly recommendation: "Use isolated networks and namespaces; publish specific ports instead of host networking.";
        readonly complexity: "small";
        readonly tags: ["security", "host-namespace"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/compose.yaml", "**/docker-compose.yml", "**/docker-compose.yaml"];
            readonly pattern: {
                readonly pattern: "(?:network_mode|pid|ipc|userns_mode):\\s*[\"']?host";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "docker-compose.dangerous-capabilities";
        readonly title: "Compose service grants dangerous capabilities";
        readonly summary: "Compose service grants dangerous capabilities";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "SYS_ADMIN, SYS_PTRACE, NET_ADMIN, and ALL approach privileged mode and enable known escapes.";
        readonly impact: "Capability-based container breakout and host network manipulation.";
        readonly recommendation: "Drop all capabilities and add back only the minimum required set.";
        readonly complexity: "small";
        readonly tags: ["security", "capabilities"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/compose.yaml", "**/docker-compose.yml", "**/docker-compose.yaml"];
            readonly pattern: {
                readonly pattern: "cap_add:[\\s\\S]{0,120}(?:SYS_ADMIN|SYS_PTRACE|NET_ADMIN|ALL)\\b";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "docker-compose.security-opt-disabled";
        readonly title: "Compose service disables security profiles";
        readonly summary: "Compose service disables security profiles";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Disabling seccomp, AppArmor, SELinux labels, or no-new-privileges removes default hardening.";
        readonly impact: "Syscall and LSM protections that block common escape techniques are turned off.";
        readonly recommendation: "Keep default profiles; ship a custom profile that allows only the required syscalls if needed.";
        readonly complexity: "small";
        readonly tags: ["security", "security-opt"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/compose.yaml", "**/docker-compose.yml", "**/docker-compose.yaml"];
            readonly pattern: {
                readonly pattern: "security_opt:[\\s\\S]{0,160}(?:seccomp[=:]\\s*unconfined|apparmor[=:]\\s*unconfined|label[=:]\\s*disable|no-new-privileges[=:]\\s*false)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "docker-compose.sensitive-port-exposed";
        readonly title: "Sensitive port published without host-IP restriction";
        readonly summary: "Sensitive port published without host-IP restriction";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Compose publishes on 0.0.0.0 by default — data-plane ports become LAN/internet-exposed.";
        readonly impact: "Open databases, caches, and admin UIs with weak or default credentials.";
        readonly recommendation: "Bind to 127.0.0.1 for local dev; use expose for inter-service traffic.";
        readonly complexity: "small";
        readonly tags: ["security", "ports"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/compose.yaml", "**/docker-compose.yml", "**/docker-compose.yaml"];
            readonly pattern: {
                readonly pattern: "ports:[\\s\\S]{0,240}[\"'](?!127\\.0\\.0\\.1)[^\"']*\\b(?:5432|3306|6379|27017|9200|11211|2375|5601|15672):";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "docker-compose.inline-secret-env";
        readonly title: "Credential literal in Compose environment";
        readonly summary: "Credential literal in Compose environment";
        readonly category: "secrets";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Compose files are committed; password/token literals become committed secrets.";
        readonly impact: "Leaked credentials for databases and third-party APIs from repository history.";
        readonly recommendation: "Use ${VAR} interpolation, env_file, or Compose secrets instead of literals.";
        readonly complexity: "small";
        readonly tags: ["secrets", "environment"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/compose.yaml", "**/docker-compose.yml", "**/docker-compose.yaml"];
            readonly pattern: {
                readonly pattern: "(?:PASSWORD|SECRET|TOKEN|API_KEY|CREDENTIAL)[A-Z0-9_]*:\\s*[\"']?(?!\\$\\{)(?!changeme)(?!example)(?!placeholder)(?!xxx)[^\\s\"'$#]{6,}";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "docker-compose.writable-git-bind";
        readonly title: "Host .git metadata is mounted writable";
        readonly summary: "The external .git directory is writable; mount it read-only to prevent permission collisions";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "A container that only needs repository metadata can still mutate host refs, config, hooks, and object state through a writable .git bind.";
        readonly impact: "Container processes can corrupt the host checkout or leave repository metadata changes that affect later developer commands.";
        readonly recommendation: "Mount .git read-only with :ro (or :ro,z when SELinux relabeling is required).";
        readonly complexity: "trivial";
        readonly tags: ["security", "bind-mount", "git"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/compose.yaml", "**/docker-compose.yml", "**/docker-compose.yaml"];
            readonly pattern: {
                readonly pattern: "^[\\t ]*-[\\t ]*[\"']?(?![^\\r\\n]*:[^\\r\\n]*:[^\\r\\n]*\\bro\\b)(?:\\.\\.?/|/|~/|\\$[A-Z_][A-Z0-9_]*/|\\$\\{[^}\\r\\n]+\\}/)(?:[^:\\r\\n]*/)?\\.git/?[\\t ]*:[^\\r\\n]+$";
                readonly flags: "im";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "docker-compose.mutable-image";
        readonly title: "Compose service uses a mutable image";
        readonly summary: "Compose service uses a mutable image";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Floating tags make deploys non-reproducible and enable tag-move supply-chain attacks.";
        readonly impact: "Unexpected image content on redeploy without a lockable pin.";
        readonly recommendation: "Pin deployed images by version tag at minimum, digest for production.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "mutable-image"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/compose.yaml", "**/docker-compose.yml", "**/docker-compose.yaml"];
            readonly pattern: {
                readonly pattern: "image:\\s*[^\\s@]+:(?:latest|main|edge)\\b";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
