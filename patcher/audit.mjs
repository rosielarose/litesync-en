// audit.mjs -- list the Chinese literals in a LiteSync bundle that
// table.json does NOT translate. Run this after a new upstream release
// to find out exactly which strings still need translating.
//
//   node audit.mjs <path-to-main.js> [table.json]
import fs from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const acorn = require(process.env.ACORN_PATH || "./vendor/acorn");
const [target, tablePath] = process.argv.slice(2);
if (!target) { console.error("usage: node audit.mjs <main.js> [table.json]"); process.exit(2); }
const table = tablePath ? JSON.parse(fs.readFileSync(tablePath, "utf8")) : {};
const src = fs.readFileSync(target, "utf8");
const ast = acorn.parse(src, { ecmaVersion: "latest", sourceType: "script",
  allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, allowHashBang: true });
const CJK = /[\u4e00-\u9fff]/;
const missing = new Set();
const visit = (n) => {
  if (!n || typeof n.type !== "string") return;
  if (n.type === "Literal" && typeof n.value === "string") {
    if (CJK.test(n.value) && !(n.value in table)) missing.add(n.value);
    return;
  }
  if (n.type === "TemplateLiteral") {
    for (const q of n.quasis) if (CJK.test(q.value.raw) && !(q.value.raw in table)) missing.add(q.value.raw);
    for (const e of n.expressions) visit(e);
    return;
  }
  for (const k of Object.keys(n)) {
    if (["start","end","type","loc","range","raw"].includes(k)) continue;
    const c = n[k];
    if (Array.isArray(c)) c.forEach(visit);
    else if (c && typeof c.type === "string") visit(c);
  }
};
visit(ast);
const list = [...missing];
console.log(list.length + " untranslated CJK literal(s):");
for (const s of list) console.log("  " + JSON.stringify(s));
