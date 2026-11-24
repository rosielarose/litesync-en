#!/usr/bin/env node
/*
 * litesync_en4.js -- rewrite LiteSync's hardcoded Chinese UI strings into English.
 *
 * WHY
 *   LiteSync 0.19.0 ships with NO i18n layer: every user-facing string is a
 *   hardcoded Chinese literal in the bundle (no t(), no locale files, no
 *   language setting). Obsidian's translation plugins cannot help -- they
 *   replace known label strings in plugins that expose them, and LiteSync
 *   exposes none. The only way to get an English UI is to rewrite the literals.
 *
 * HOW
 *   Uses acorn (a real JavaScript parser) to locate every string literal and
 *   every template-literal chunk in the bundle. That gives exact, authoritative
 *   source ranges -- no hand-rolled scanning, no guessing about where a string
 *   ends. Only the ranges that hold a translatable literal are rewritten;
 *   everything else, including ${...} interpolations, is copied verbatim.
 *
 * SAFETY
 *   - Backs up main.js to main.js.zh-backup (once).
 *   - The output is re-parsed with acorn AND checked with `node --check`.
 *   - The count of string literals and template chunks must be identical
 *     before and after; the script refuses to install otherwise.
 *   - Idempotent: re-running on a translated file is a no-op.
 *
 * Usage: node litesync_en4.js <path-to-main.js> <table.json>
 */
"use strict";

const fs = require("fs");
const path = require("path");
const cp = require("child_process");

// acorn is vendored next to this script, so the toolchain works from a clone
// with no npm install. ACORN_PATH overrides it (absolute path).
const acorn = require(
  process.env.ACORN_PATH || path.join(__dirname, "vendor/acorn")
);

const BS = String.fromCharCode(92);
const CJK = /[一-鿿]/;

// ---------------------------------------------------------------------------
// Escape decoding -- must match how the translation table was built.
// Handles \uXXXX, \u{XXXXX}, \xNN. Deliberately does NOT touch \n or \t:
// those stay as escape sequences so they round-trip unchanged.
// ---------------------------------------------------------------------------
function decodeEscapes(text) {
  const out = [];
  let i = 0;
  const n = text.length;
  // Sticky flag: the match MUST be at position 0 of the slice. Without it,
  // exec() would find an escape further along the string and corrupt the key.
  const re = new RegExp(BS + BS + "u\\{([0-9a-fA-F]+)\\}|" + BS + BS + "u([0-9a-fA-F]{4})|" + BS + BS + "x([0-9a-fA-F]{2})", "y");
  while (i < n) {
    if (text[i] === BS && i + 1 < n) {
      let b = 0;
      let j = i - 1;
      while (j >= 0 && text[j] === BS) { b++; j--; }
      if (b % 2 === 0) {
        re.lastIndex = 0;
        const m = re.exec(text.slice(i));
        if (m) {
          const code = parseInt(m[1] || m[2] || m[3], 16);
          out.push(String.fromCodePoint(code));
          i += m[0].length;
          continue;
        }
      }
    }
    out.push(text[i]);
    i++;
  }
  return out.join("");
}

// Escape English text for insertion into a JS literal of the given quote style.
// NOTE: backslashes are deliberately NOT doubled -- the table values already
// contain intended escape sequences (e.g. "\\n") that must survive verbatim.
function escapeFor(text, quote) {
  if (quote === '"') return text.split('"').join(BS + '"');
  if (quote === "'") return text.split("'").join(BS + "'");
  return text.split("`").join(BS + "`").split("${").join(BS + "${");
}

// ---------------------------------------------------------------------------
// Walk the AST and collect the editable ranges.
// ---------------------------------------------------------------------------
function collectEdits(src, ast, table) {
  const edits = [];
  let strCount = 0;
  let chunkCount = 0;
  let cjkLeft = 0;

  const visit = (node) => {
    if (!node || typeof node.type !== "string") return;

    if (node.type === "Literal" && typeof node.value === "string") {
      strCount++;
      const quote = src[node.start];
      const body = src.slice(node.start + 1, node.end - 1);
      const key = decodeEscapes(body);
      if (CJK.test(key)) {
        const repl = table[key];
        if (repl !== undefined) {
          edits.push({
            start: node.start,
            end: node.end,
            text: quote + escapeFor(repl, quote) + quote,
          });
        } else {
          cjkLeft++;
        }
      }
      return;
    }

    if (node.type === "TemplateLiteral") {
      // Each quasi is a literal-text chunk; the ${...} holes are NOT quasis
      // and are therefore never touched.
      for (const q of node.quasis) {
        chunkCount++;
        const raw = src.slice(q.start, q.end);
        const key = decodeEscapes(raw);
        if (CJK.test(key)) {
          const repl = table[key];
          if (repl !== undefined) {
            edits.push({ start: q.start, end: q.end, text: escapeFor(repl, "`") });
          } else {
            cjkLeft++;
          }
        }
      }
      // Do not descend into the expressions: their strings are separate
      // Literal nodes and will be visited on their own.
      for (const expr of node.expressions) visit(expr);
      return;
    }

    // Object properties hold most UI strings in the VALUE position
    // ({ text: "Test Connection" }). The KEY must never be translated --
    // renaming a property would break the code.
    if (node.type === "Property" || node.type === "PropertyDefinition" ||
        node.type === "MethodDefinition") {
      if (node.value && typeof node.value.type === "string") visit(node.value);
      if (node.key && node.computed && typeof node.key.type === "string") visit(node.key);
      return;
    }

    for (const key of Object.keys(node)) {
      if (key === "start" || key === "end" || key === "type" || key === "loc" ||
          key === "range" || key === "raw" || key === "sourceFile") {
        continue;
      }
      const child = node[key];
      if (Array.isArray(child)) {
        for (const c of child) if (c && typeof c.type === "string") visit(c);
      } else if (child && typeof child.type === "string") {
        visit(child);
      }
    }
  };

  visit(ast);
  return { edits, strCount, chunkCount, cjkLeft };
}

function parse(src, label) {
  try {
    return acorn.parse(src, {
      ecmaVersion: "latest",
      sourceType: "script",
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      allowHashBang: true,
      locations: false,
    });
  } catch (err) {
    console.error("ERROR: acorn could not parse " + label + ": " + err.message);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function main() {
  const [target, tablePath] = process.argv.slice(2);
  if (!target || !tablePath) {
    console.log(fs.readFileSync(__filename, "utf8").split("*/")[0] + "*/");
    process.exit(2);
  }
  if (!fs.existsSync(target)) {
    console.error("ERROR: " + target + " not found");
    process.exit(1);
  }

  const table = JSON.parse(fs.readFileSync(tablePath, "utf8"));
  console.log("  translation table: " + Object.keys(table).length + " entries");

  const src = fs.readFileSync(target, "utf8");

  const backup = target + ".zh-backup";
  if (!fs.existsSync(backup)) {
    fs.copyFileSync(target, backup);
    console.log("  backup written: " + backup);
  }

  const ast = parse(src, "the original");
  const { edits, strCount, chunkCount, cjkLeft } = collectEdits(src, ast, table);
  console.log("  literal-text chunks translated: " + edits.length);
  console.log("  CJK chunks left untouched: " + cjkLeft);

  // Splice: copy the source verbatim, replacing only the edited ranges.
  edits.sort((a, b) => a.start - b.start);
  const parts = [];
  let last = 0;
  for (const e of edits) {
    if (e.start < last) {
      console.error("ERROR: overlapping edit ranges; NOT installing.");
      process.exit(1);
    }
    parts.push(src.slice(last, e.start));
    parts.push(e.text);
    last = e.end;
  }
  parts.push(src.slice(last));
  const out = parts.join("");

  // Validate: re-parse with acorn and compare structure.
  const ast2 = parse(out, "the translated bundle");
  const after = collectEdits(out, ast2, {});
  if (after.strCount !== strCount || after.chunkCount !== chunkCount) {
    console.error(
      "ERROR: structure changed (strings " + strCount + "->" + after.strCount +
      ", chunks " + chunkCount + "->" + after.chunkCount + "); NOT installing."
    );
    process.exit(1);
  }
  console.log("  strings preserved: " + after.strCount);
  console.log("  template chunks preserved: " + after.chunkCount);

  // Validate: node --check.
  const tmp = target + ".tmp.js";
  fs.writeFileSync(tmp, out);
  const chk = cp.spawnSync("node", ["--check", tmp], { encoding: "utf8" });
  if (chk.status !== 0) {
    console.error("ERROR: translated bundle failed node --check; NOT installing.");
    console.error((chk.stderr || "").slice(0, 3000));
    fs.unlinkSync(tmp);
    process.exit(1);
  }
  console.log("  node --check: OK");

  fs.renameSync(tmp, target);
  console.log("  wrote " + target);
  console.log("  size: " + src.length.toLocaleString() + " -> " + out.length.toLocaleString() + " bytes");
}

main();
