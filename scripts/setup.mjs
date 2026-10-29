// Idempotent, non-interactive development setup.
//   - creates .env from .env.example
//   - creates ./data
//   - creates backend/.venv and installs Python requirements (only when they changed)
//   - installs Node dependencies when missing
//   - runs database migrations
//   - reports Nmap availability
import { copyFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  BACKEND, IS_WIN, ROOT, STAMP, VENV, VENV_PYTHON, c, capture, detectNmap, findSystemPython, log,
  nodeReady, pythonReady, requirementsHash, run,
} from './lib.mjs';

function fail(msg) {
  console.error(`\n${c.red('[setup] ERROR:')} ${msg}\n`);
  process.exit(1);
}

export function ensureEnvFile() {
  const env = join(ROOT, '.env');
  if (!existsSync(env)) {
    copyFileSync(join(ROOT, '.env.example'), env);
    log('created .env from .env.example');
  }
  mkdirSync(join(ROOT, 'data'), { recursive: true });
}

export function ensurePython({ force = false } = {}) {
  if (!force && pythonReady()) return;
  if (!existsSync(VENV_PYTHON)) {
    const py = findSystemPython();
    if (!py) fail('Python 3.10+ was not found on PATH. Install Python 3.10 or newer and re-run `npm run setup`.');
    log(`creating virtualenv backend/.venv with Python ${py.version}`);
    let status = run(py.cmd, [...py.pre, '-m', 'venv', VENV]);
    if (status !== 0 && capture('uv', ['--version'])) {
      log('python -m venv failed, retrying with uv');
      status = run('uv', ['venv', '--seed', VENV]);
    }
    if (status !== 0 || !existsSync(VENV_PYTHON)) {
      fail(
        'Could not create the Python virtualenv.\n' +
        (IS_WIN ? '' : '  On Debian/Ubuntu install the venv module:  sudo apt-get install -y python3-venv\n') +
        '  Then re-run:  npm run setup',
      );
    }
  }
  log('installing Python requirements (backend/requirements-dev.txt)');
  const pipArgs = ['-m', 'pip', 'install', '--disable-pip-version-check', '-q', '-r', join(BACKEND, 'requirements-dev.txt')];
  if (run(VENV_PYTHON, pipArgs) !== 0) fail('pip install failed. See the output above.');
  writeFileSync(STAMP, requirementsHash());
}

export function ensureNode() {
  if (nodeReady()) return;
  log('installing Node dependencies (npm install)');
  // Prefer the npm that launched us (npm_execpath) over whatever `npm` resolves to on PATH
  const npmCli = process.env.npm_execpath;
  const status = npmCli && npmCli.endsWith('.js')
    ? run(process.execPath, [npmCli, 'install', '--no-audit', '--no-fund'])
    : run(IS_WIN ? 'npm.cmd' : 'npm', ['install', '--no-audit', '--no-fund'], { shell: IS_WIN });
  if (status !== 0) {
    fail('npm install failed. See the output above.');
  }
}

export function migrate() {
  // Uses .env (usually SQLite). Production Postgres is migrated by scripts/run.ps1.
  log('running database migrations (dev .env - production uses run.ps1 + .env.production)');
  if (run(VENV_PYTHON, ['-m', 'app.cli', 'migrate'], { cwd: BACKEND }) !== 0) {
    fail('Database migration failed. See the output above. For a disposable dev DB run: npm run db:reset');
  }
}

export function reportNmap() {
  const v = detectNmap();
  if (v) log(`${c.green('nmap detected')} (version ${v})`);
  else log(`${c.yellow('nmap NOT detected')} - the app will start, but only the mock scanner can run. Install nmap for real scans.`);
}

/** Windows host: Playwright Chromium + ffmpeg + FreeRDP + subfinder/dnsx (soft-fail; optional for scans).
 *  Linux: subfinder/dnsx from the pinned, sha256-verified releases in scripts/tools-manifest.json. */
export function ensureCaptureTools() {
  if (process.env.NF_SKIP_CAPTURE_TOOLS === '1') {
    log('skipping capture-tools install (NF_SKIP_CAPTURE_TOOLS=1)');
    return;
  }
  if (!IS_WIN) {
    ensureDnsTools();
    return;
  }
  const script = join(ROOT, 'scripts', 'install-capture-tools.ps1');
  if (!existsSync(script)) return;
  log('ensuring host tools (Playwright / ffmpeg / FreeRDP / subfinder / dnsx)');
  const status = run('powershell.exe', [
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script,
  ]);
  if (status !== 0) {
    log(c.yellow('capture-tools install reported issues - RDP/RTSP/HTTP stills and Domain scan steps may soft-skip until tools are on PATH'));
  }
}

/** Linux / macOS: subfinder + dnsx into data/tools/bin unless already on PATH (soft-fail). */
export function ensureDnsTools() {
  const script = join(ROOT, 'scripts', 'install-dns-tools.py');
  if (!existsSync(script) || !existsSync(VENV_PYTHON)) return;
  log('ensuring Domain scan tools (subfinder / dnsx)');
  if (run(VENV_PYTHON, ['-I', script]) !== 0) {
    log(c.yellow('subfinder/dnsx install reported issues - Domain scan passive/wordlist steps stay disabled until installed'));
  }
}

export function ensureAll({ quiet = false } = {}) {
  ensureEnvFile();
  ensureNode();
  ensurePython();
  migrate();
  reportNmap();
  ensureCaptureTools();
  if (!quiet) log(c.green('setup complete. Start the app with: npm run dev'));
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  ensureEnvFile();
  ensureNode();
  ensurePython({ force: process.argv.includes('--force') });
  migrate();
  reportNmap();
  if (!process.argv.includes('--skip-capture-tools')) ensureCaptureTools();
  log(c.green('setup complete. Start the app with: npm run dev'));
}
