import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

type SignoffDoc = {
  approved: boolean;
  approved_by: string;
  approved_at: string;
  release_version: string;
  checklist_ref?: string;
  notes?: string;
};

function fail(message: string): never {
  // eslint-disable-next-line no-console
  console.error(message);
  process.exit(1);
}

function main(): void {
  const target = process.env.SIGNOFF_FILE ?? path.resolve(process.cwd(), "..", "docs", "operations", "staging-signoff.json");
  if (!existsSync(target)) {
    fail(`Staging sign-off file not found: ${target}`);
  }

  const raw = readFileSync(target, "utf8");
  let parsed: SignoffDoc;
  try {
    parsed = JSON.parse(raw) as SignoffDoc;
  } catch {
    fail(`Invalid JSON in sign-off file: ${target}`);
  }

  if (parsed.approved !== true) {
    fail(`Release blocked: staging sign-off is not approved in ${target}.`);
  }
  if (!parsed.approved_by || !parsed.approved_at || !parsed.release_version) {
    fail(`Release blocked: sign-off document is missing required fields in ${target}.`);
  }

  // eslint-disable-next-line no-console
  console.log(`Staging sign-off validated for release ${parsed.release_version} by ${parsed.approved_by} at ${parsed.approved_at}.`);
}

main();
