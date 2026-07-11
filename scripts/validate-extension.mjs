import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(path.join(root, "manifest.json"), "utf8"));

assert.equal(manifest.manifest_version, 3);
assert.equal(manifest.minimum_chrome_version, "130");
assert.equal(manifest.incognito, "not_allowed");
assert.deepEqual(manifest.permissions, ["cookies"]);
assert.deepEqual(manifest.optional_host_permissions, ["http://*/*", "https://*/*"]);
assert.equal(manifest.content_scripts, undefined);
assert.equal(manifest.externally_connectable, undefined);
assert.equal(manifest.web_accessible_resources, undefined);
assert.equal(
  manifest.content_security_policy.extension_pages,
  "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; connect-src 'none'; img-src 'self' data:; media-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'",
);

const sourceFiles = (await readdir(root, { recursive: true }))
  .filter((entry) => entry.endsWith(".js") && !entry.includes("node_modules"))
  .filter((entry) => !entry.startsWith("scripts"));

const forbiddenNetworkApis = [
  /\bfetch\s*\(/u,
  /\bXMLHttpRequest\b/u,
  /\bWebSocket\b/u,
  /\bEventSource\b/u,
  /\bsendBeacon\s*\(/u,
];

for (const relative of sourceFiles) {
  const source = await readFile(path.join(root, relative), "utf8");
  for (const pattern of forbiddenNetworkApis) {
    assert.equal(pattern.test(source), false, `${relative} contains forbidden network API ${pattern}`);
  }
}

console.log(`Validated manifest and ${sourceFiles.length} JavaScript source files: no network APIs found.`);
