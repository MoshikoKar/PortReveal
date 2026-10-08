// Run the backend virtualenv's Python inside ./backend, preparing it first if needed.
// Usage: node scripts/py.mjs -m pytest -q
import { spawnSync } from 'node:child_process';
import { BACKEND, VENV_PYTHON } from './lib.mjs';
import { ensureEnvFile, ensurePython } from './setup.mjs';

ensureEnvFile();
ensurePython();
const r = spawnSync(VENV_PYTHON, process.argv.slice(2), { stdio: 'inherit', cwd: BACKEND });
process.exit(r.status ?? 1);
