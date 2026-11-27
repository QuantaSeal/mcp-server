// Fails when the places that state this server's version or tool count disagree with the source of truth.
//
//   node scripts/check-versions.mjs
//
// Version: package.json is the single source. server.json (registry listing), smithery.yaml (Smithery listing) must match it,
// and src/server.ts must read it rather than carry its own literal (it once reported 1.1.0 while 1.1.5 was published).
// Tool count: the TOOLS array in src/server.ts is the source. Every sentence in the listing and in the server's own
// description that states "<n> tools" must equal it.
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const failures = [];
const fail = (message) => failures.push(message);

const version = JSON.parse(read("package.json")).version;

const serverJson = JSON.parse(read("server.json"));
if (serverJson.version !== version) fail(`server.json version ${serverJson.version} != package.json ${version}`);
for (const entry of serverJson.packages ?? []) {
  if (entry.version !== version) fail(`server.json packages[] version ${entry.version} != package.json ${version}`);
}

const smithery = read("smithery.yaml");
const smitheryVersion = smithery.match(/^version:\s*(\S+)\s*$/m)?.[1];
if (smitheryVersion !== version) fail(`smithery.yaml version ${smitheryVersion} != package.json ${version}`);

const source = read("src/server.ts");
if (/const\s+VERSION\s*(?::\s*string\s*)?=\s*["']/.test(source)) {
  fail('src/server.ts has a literal VERSION; it must be read from package.json');
}
if (!source.includes('"../package.json"')) fail("src/server.ts does not read ../package.json");

const start = source.indexOf("const TOOLS");
const end = source.indexOf("\n];", start);
const toolCount = [...source.slice(start, end).matchAll(/^ {4}name:\s*"[a-z_]+"/gm)].length;
if (start < 0 || end < 0 || toolCount === 0) fail("could not find the TOOLS array in src/server.ts");

for (const [file, text] of [["smithery.yaml", smithery], ["src/server.ts", source]]) {
  for (const match of text.matchAll(/\b(\d+)\s+tools\b/g)) {
    if (Number(match[1]) !== toolCount) fail(`${file} says "${match[0]}" but the server defines ${toolCount} tools`);
  }
}

if (failures.length > 0) {
  console.error(failures.map((f) => `FAIL ${f}`).join("\n"));
  process.exit(1);
}
console.log(`ok: version ${version} in package.json, server.json, smithery.yaml and read by src/server.ts; ${toolCount} tools match every stated count`);
