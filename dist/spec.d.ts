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
    readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/docker-compose.yml"];
    readonly rules: [{
        readonly id: "docker-compose.privileged";
        readonly title: "Compose service runs privileged";
        readonly summary: "Compose service runs privileged";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Compose service runs privileged weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Remove privileged mode and add only required capabilities.";
        readonly complexity: "small";
        readonly tags: ["security", "privileged"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/docker-compose.yml"];
            readonly pattern: {
                readonly pattern: "privileged:\\s*true";
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
        readonly whyItMatters: "Compose service joins a host namespace weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Use isolated networks and PID/IPC namespaces.";
        readonly complexity: "small";
        readonly tags: ["security", "host-namespace"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/docker-compose.yml"];
            readonly pattern: {
                readonly pattern: "(?:network_mode|pid|ipc):\\s*[\"']?host";
                readonly flags: "i";
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
        readonly whyItMatters: "Compose service uses a mutable image weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Pin deployed images by digest.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "mutable-image"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "**/compose.yml", "**/docker-compose.yml"];
            readonly pattern: {
                readonly pattern: "image:\\s*[^\\s]+:(?:latest|main|edge)\\b";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
