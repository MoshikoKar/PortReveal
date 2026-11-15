#!/usr/bin/env node
// Keep PortReveal version strings in sync across manifests.
//
// Usage:
//   node scripts/version.mjs check [v1.2.3|1.2.3]
//   node scripts/version.mjs bump <major|minor|patch|1.2.3>
//
// Manifests:
//   package.json, frontend/package.json, package-lock.json (root + packages),
//   backend/pyproject.toml, backend/app/__init__.py

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT } from './lib.mjs';

const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;

const PATHS = {
  rootPkg: join(ROOT, 'package.json'),
  frontendPkg: join(ROOT, 'frontend', 'package.json'),
  lock: join(ROOT, 'package-lock.json'),
  pyproject: join(ROOT, 'backend', 'pyproject.toml'),
  initPy: join(ROOT, 'backend', 'app', '__init__.py'),
};

function die(msg) {
  console.error(msg);
  process.exit(1);
}

function normalize(raw) {
  const s = String(raw || '').trim().replace(/^v/i, '');
  if (!SEMVER.test(s)) die(`invalid version: ${raw} (expected X.Y.Z)`);
  return s;
}

function bumpSemver(current, part) {
  const m = current.match(SEMVER);
  if (!m) die(`cannot bump invalid current version: ${current}`);
  let [major, minor, patch] = m.slice(1).map(Number);
  if (part === 'major') {
    major += 1;
    minor = 0;
    patch = 0;
  } else if (part === 'minor') {
    minor += 1;
    patch = 0;
  } else if (part === 'patch') {
    patch += 1;
  } else {
    die(`unknown bump: ${part} (use major, minor, patch, or X.Y.Z)`);
  }
  return `${major}.${minor}.${patch}`;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function writeJson(path, data) {
  writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`);
}

function readPyprojectVersion(text) {
  const m = text.match(/^version\s*=\s*"([^"]+)"/m);
  if (!m) die('backend/pyproject.toml: missing version = "..."');
  return m[1];
}

function writePyprojectVersion(text, version) {
  if (!/^version\s*=\s*"[^"]+"/m.test(text)) die('backend/pyproject.toml: missing version field');
  return text.replace(/^version\s*=\s*"[^"]+"/m, `version = "${version}"`);
}

function readInitVersion(text) {
  const m = text.match(/^__version__\s*=\s*"([^"]+)"/m);
  if (!m) die('backend/app/__init__.py: missing __version__');
  return m[1];
}

function writeInitVersion(text, version) {
  if (!/^__version__\s*=\s*"[^"]+"/m.test(text)) die('backend/app/__init__.py: missing __version__');
  return text.replace(/^__version__\s*=\s*"[^"]+"/m, `__version__ = "${version}"`);
}

function readVersions() {
  const rootPkg = readJson(PATHS.rootPkg);
  const frontendPkg = readJson(PATHS.frontendPkg);
  const lock = readJson(PATHS.lock);
  const pyprojectText = readFileSync(PATHS.pyproject, 'utf8');
  const initText = readFileSync(PATHS.initPy, 'utf8');

  return {
    'package.json': rootPkg.version,
    'frontend/package.json': frontendPkg.version,
    'package-lock.json (root)': lock.version,
    'package-lock.json (packages."")': lock.packages?.['']?.version,
    'package-lock.json (packages.frontend)': lock.packages?.frontend?.version,
    'backend/pyproject.toml': readPyprojectVersion(pyprojectText),
    'backend/app/__init__.py': readInitVersion(initText),
  };
}

function checkVersions(expected) {
  const versions = readVersions();
  const values = Object.values(versions);
  const unique = [...new Set(values)];
  if (unique.length !== 1) {
    console.error('version mismatch across manifests:');
    for (const [k, v] of Object.entries(versions)) console.error(`  ${k}: ${v}`);
    process.exit(1);
  }
  const actual = unique[0];
  if (expected != null && actual !== expected) {
    die(`manifests are ${actual}, expected ${expected}`);
  }
  console.log(`versions ok: ${actual}`);
  return actual;
}

function writeVersions(version) {
  const rootPkg = readJson(PATHS.rootPkg);
  rootPkg.version = version;
  writeJson(PATHS.rootPkg, rootPkg);

  const frontendPkg = readJson(PATHS.frontendPkg);
  frontendPkg.version = version;
  writeJson(PATHS.frontendPkg, frontendPkg);

  const lock = readJson(PATHS.lock);
  lock.version = version;
  if (!lock.packages?.['']) die('package-lock.json: missing packages[""]');
  lock.packages[''].version = version;
  if (!lock.packages?.frontend) die('package-lock.json: missing packages.frontend');
  lock.packages.frontend.version = version;
  writeJson(PATHS.lock, lock);

  const pyprojectText = readFileSync(PATHS.pyproject, 'utf8');
  writeFileSync(PATHS.pyproject, writePyprojectVersion(pyprojectText, version));

  const initText = readFileSync(PATHS.initPy, 'utf8');
  writeFileSync(PATHS.initPy, writeInitVersion(initText, version));
}

function usage() {
  die(`usage:
  node scripts/version.mjs check [vX.Y.Z|X.Y.Z]
  node scripts/version.mjs bump <major|minor|patch|X.Y.Z>`);
}

function main(argv) {
  const [cmd, arg] = argv;
  if (cmd === 'check') {
    const expected = arg == null || arg === '' ? null : normalize(arg);
    checkVersions(expected);
    return;
  }
  if (cmd === 'bump') {
    if (!arg) usage();
    const current = checkVersions(null);
    const next = ['major', 'minor', 'patch'].includes(arg) ? bumpSemver(current, arg) : normalize(arg);
    writeVersions(next);
    checkVersions(next);
    console.log(`bumped ${current} -> ${next}`);
    return;
  }
  usage();
}

main(process.argv.slice(2));
