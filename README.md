# litesync-en — an English UI for LiteSync

LiteSync ships with **no i18n layer**: every user-facing string in the plugin
bundle is a hardcoded Chinese literal. Obsidian's translation plugins cannot
help, because they only work on plugins that *expose* translatable strings,
and LiteSync exposes none. The only way to get an English UI is to rewrite the
literals.

This repo holds that rewrite, the translation table it uses, and the tooling to
rebuild and publish a new release when upstream ships one.

## Why this exists (the short version)

| | |
|---|---|
| Upstream | `kjoner/litesync` — the plugin, MIT, no i18n |
| Problem | every UI string is Chinese; the plugin *is* the i18n surface |
| Fix | parse the bundle with a real JS parser and splice English over the literal ranges |
| Published as | a GitHub release, because **BRAT installs plugins from releases** — a repo tree alone does nothing |

## What is in here

```
main.js                  the patched 0.19.0 bundle (English UI)
manifest.json            plugin manifest, version 0.19.1
styles.css               upstream, unchanged
patcher/
  litesync_en4.js        the patcher: acorn -> literal ranges -> English
  table.json             667 entries: Chinese literal -> English
  audit.mjs              lists the CJK literals the table does NOT cover
  vendor/node_modules/   acorn 8.19, vendored so this works with no npm install
tools/publish.sh         upstream release -> patched bundle -> GitHub release
```

### How the patcher works

`patcher/litesync_en4.js` parses `main.js` with **acorn** (a real JavaScript
parser, not a hand-rolled scanner) and collects the exact source ranges of
every string literal and every template-literal chunk. Only ranges whose
*decoded* content contains CJK are looked up in `table.json`; the English
replacement is spliced over that range, and **every other byte — including
`${...}` interpolations — is copied verbatim**.

It refuses to install a broken bundle:

- the output is re-parsed with acorn, and the count of string literals and
  template chunks must be **identical** to the original;
- `node --check` must pass;
- the original is kept as `main.js.zh-backup` (once);
- it is idempotent — re-running on a translated file is a no-op.

A hand-rolled string scanner was tried first and silently dropped 415 of 651
template interpolations, which broke the plugin's error messages (the error
text rendered with an empty message). Use acorn.

## Using the patch on a machine

```bash
# a plugin checkout on this machine
ACORN_PATH=patcher/vendor/acorn \
  node patcher/litesync_en4.js \
    ~/.config/obsidian/plugins/litesync/main.js \
    patcher/table.json
```

Then restart Obsidian. On the Dell and the Mac this is wrapped in
`~/.local/bin/litesync-en-apply.sh`.

**An Obsidian community-plugin auto-update overwrites `main.js` and the UI
silently reverts to Chinese.** Re-apply after every upstream release.

## Publishing a new release

When upstream ships a new version:

```bash
# 1. see what the table does not cover yet
node patcher/audit.mjs /path/to/new-upstream-main.js patcher/table.json
#    -> "N untranslated CJK literal(s)" — translate those and add them to
#       patcher/table.json (the key is the DECODED literal, exactly as printed)

# 2. build and publish (downloads upstream, patches, bumps the version,
#    creates the release with main.js + manifest.json + styles.css as assets)
GITHUB_TOKEN=... tools/publish.sh 0.19.1 0.19.2
```

**Why the version is bumped past upstream's.** Obsidian's community updater
only ever moves *up*. If the installed manifest says `0.19.1` while the
registry's newest is `0.19.0`, the registry never overwrites the English
build with the Chinese one. Keep the manifest id `litesync` so BRAT replaces
the plugin in place instead of installing a second copy.

## Installing on the phone

The phone cannot receive the patch through sync (`.obsidian/` is not synced)
and iOS Files will not show the hidden `.obsidian` folder, so the bundle
cannot be dropped in by hand. **BRAT** is the route:

1. BRAT → *Add beta plugin* → `rosielarose/litesync-en`
2. Install version `0.19.1`
3. Fully quit and reopen Obsidian

The repo is public, so BRAT needs no GitHub token. **BRAT's auto-update is
OFF on the phone** — otherwise BRAT would overwrite the installed build every
time a new release is published here.

If the repo ever goes private, BRAT needs a GitHub token (it stores it in
Obsidian's SecretStorage).
