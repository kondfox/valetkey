// Runs one command through the srt *library* (SandboxManager), which, unlike the srt CLI,
// accepts a config without network.allowedDomains. Usage: node lib-run.mjs <srt-pkg-dir> <cfg.json> <cmd>
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const [pkg, cfgPath, cmd] = process.argv.slice(2);
const { SandboxManager } = await import(pathToFileURL(path.join(pkg, 'dist/index.js')).href);
const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
await SandboxManager.initialize(cfg);
const wrapped = await SandboxManager.wrapWithSandbox(cmd);
if (process.env.PROBE_DUMP_WRAPPED) fs.writeFileSync(process.env.PROBE_DUMP_WRAPPED, wrapped);
const r = spawnSync(wrapped, { shell: true, stdio: 'inherit' });
await SandboxManager.reset();
process.exit(r.status ?? 1);
