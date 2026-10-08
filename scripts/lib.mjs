// Shared helpers for the development scripts. No third-party imports here:
// these run before `npm install` has necessarily completed.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const BACKEND = join(ROOT, 'backend');
export const VENV = join(BACKEND, '.venv');
export const IS_WIN = process.platform === 'win32';
export const VENV_PYTHON = IS_WIN ? join(VENV, 'Scripts', 'python.exe') : join(VENV, 'bin', 'python');
export const STAMP = join(VENV, '.requirements-stamp');

export const c = {
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
};

export function log(msg) {
  console.log(`${c.cyan('[setup]')} ${msg}`);
}

export function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: 'inherit', cwd: ROOT, ...opts });
  if (r.error) throw r.error;
  return r.status ?? 1;
}

export function capture(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', cwd: ROOT, ...opts });
  if (r.error || r.status !== 0) return null;
  return `${r.stdout || ''}${r.stderr || ''}`.trim();
}

/** Minimal .env reader (KEY=VALUE, # comments). Real env vars take precedence. */
export function readEnv() {
  const env = {};
  const file = join(ROOT, '.env');
  if (existsSync(file)) {
    for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
      if (!m) continue;
      let v = m[2];
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
      env[m[1]] = v;
    }
  }
  return { ...env, ...process.env };
}

/** Find a system Python >= 3.10 to create the virtualenv with. */
export function findSystemPython() {
  const candidates = IS_WIN
    ? [['py', ['-3']], ['python', []], ['python3', []]]
    : [['python3', []], ['python', []]];
  for (const [cmd, pre] of candidates) {
    const out = capture(cmd, [...pre, '-c', 'import sys; print("%d.%d" % sys.version_info[:2])']);
    if (!out) continue;
    const [maj, min] = out.split(/\s+/).pop().split('.').map(Number);
    if (maj === 3 && min >= 10) return { cmd, pre, version: `${maj}.${min}` };
  }
  return null;
}

export function requirementsHash() {
  const h = createHash('sha256');
  for (const f of ['requirements.txt', 'requirements-dev.txt']) {
    h.update(readFileSync(join(BACKEND, f)));
  }
  return h.digest('hex');
}

export function pythonReady() {
  return existsSync(VENV_PYTHON) && existsSync(STAMP) && readFileSync(STAMP, 'utf8').trim() === requirementsHash();
}

export function nodeReady() {
  return existsSync(join(ROOT, 'node_modules', 'concurrently')) && existsSync(join(ROOT, 'node_modules', 'vite'));
}

export function detectNmap(env = readEnv()) {
  const nmap = env.NMAP_PATH || 'nmap';
  const out = capture(nmap, ['--version']);
  if (!out) return null;
  const m = out.match(/Nmap version (\S+)/);
  return m ? m[1] : 'unknown';
}
