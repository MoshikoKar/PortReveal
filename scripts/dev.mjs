// Start the complete development environment (backend + frontend) with hot reload.
//   node scripts/dev.mjs            -> both
//   node scripts/dev.mjs backend    -> backend only
//   node scripts/dev.mjs frontend   -> frontend only
import net from 'node:net';
import { join } from 'node:path';
import { BACKEND, IS_WIN, ROOT, c, readEnv } from './lib.mjs';
import { ensureAll } from './setup.mjs';

const which = process.argv[2] || 'all';
ensureAll({ quiet: true });

const env = readEnv();
const backendHost = env.BACKEND_HOST || '127.0.0.1';
const backendPort = Number(env.BACKEND_PORT || 8000);
const frontendPort = Number(env.FRONTEND_PORT || 5173);

function portFree(port, host) {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.once('listening', () => srv.close(() => resolve(true)));
    srv.listen(port, host);
  });
}

const commands = [];
if (which === 'all' || which === 'backend') {
  if (!(await portFree(backendPort, backendHost))) {
    console.error(c.red(`\nPort ${backendPort} is already in use (backend). Stop the other process or set BACKEND_PORT in .env.\n`));
    process.exit(1);
  }
  // Relative paths (no quoting) - cmd.exe mangles commands that start and end with quotes
  const py = IS_WIN ? join('.venv', 'Scripts', 'python.exe') : '.venv/bin/python';
  commands.push({
    name: 'backend',
    prefixColor: 'magenta',
    cwd: BACKEND,
    command: `${py} -m uvicorn app.main:app --reload --reload-dir app --host ${backendHost} --port ${backendPort} --log-level warning`,
  });
}
if (which === 'all' || which === 'frontend') {
  commands.push({
    name: 'frontend',
    prefixColor: 'cyan',
    cwd: join(ROOT, 'frontend'),
    // Run vite through node directly (no nested npm call: more robust across shells/OSes)
    command: 'node ../node_modules/vite/bin/vite.js',
  });
}

const { default: concurrently } = await import('concurrently');
console.log(c.bold('\nNetwork Finder development environment'));
if (which !== 'backend') console.log(`  UI:      ${c.green(`http://localhost:${frontendPort}`)}`);
if (which !== 'frontend') console.log(`  API:     ${c.green(`http://${backendHost}:${backendPort}/api/health`)}`);
console.log(`  Login:   ${env.DEV_ADMIN_USERNAME || 'admin'} / ${env.DEV_ADMIN_PASSWORD || 'admin'} (dev seed)`);
console.log('  Stop:    Ctrl+C\n');

const { result } = concurrently(commands, {
  prefix: 'name',
  killOthersOn: ['failure', 'success'],
  restartTries: 0,
});
result.then(() => process.exit(0), () => process.exit(1));
