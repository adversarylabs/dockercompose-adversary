import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

test("an unrelated Compose edit does not surface a legacy mutable image", async () => {
  const repo = await repositoryWithLegacyCompose();
  await writeFile(join(repo, "compose.yml"), compose("new unrelated diagnostic"));

  const result = await changedReview(repo, ["compose.yml"]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "docker-compose.mutable-image"),
    false,
  );
});

test("an added Compose file remains fully eligible", async () => {
  const repo = await repositoryWithLegacyCompose();
  await writeFile(join(repo, "docker-compose.yml"), compose("added file"));

  const result = await changedReview(repo, ["docker-compose.yml"]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "docker-compose.mutable-image"),
    true,
  );
});

test("an unchanged first match does not hide a later changed match", async () => {
  const repo = await repositoryWithLegacyCompose();
  await writeFile(join(repo, "compose.yml"), twoImages("1.2.3"));
  await execute("git", ["add", "compose.yml"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "two image fixture"], { cwd: repo });
  await writeFile(join(repo, "compose.yml"), twoImages("latest"));

  const result = await changedReview(repo, ["compose.yml"], true);
  const observation = result.rawObservations?.find(
    (item) => item.ruleId === "docker-compose.mutable-image",
  );
  assert.equal(observation?.location?.line, 7);
  assert.match(observation?.location?.snippet ?? "", /worker:latest/);
});

async function repositoryWithLegacyCompose(): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "dockercompose-change-local-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  await writeFile(join(repo, "compose.yml"), compose("old diagnostic"));
  await execute("git", ["add", "compose.yml"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  return repo;
}

function compose(diagnostic: string): string {
  return `services:
  app:
    image: example/app:latest
    environment:
      DIAGNOSTIC: ${JSON.stringify(diagnostic)}
`;
}

function twoImages(workerTag: string): string {
  return `services:
  app:
    image: example/app:latest
  worker:
    environment:
      MODE: worker
    image: example/worker:${workerTag}
`;
}

async function changedReview(
  repoPath: string,
  changedFiles: string[],
  includeRawObservations = false,
) {
  return createApp().run({
    includeRawObservations,
    input: {
      source: { path: repoPath },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
  });
}
