'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { test } = require('node:test');
const zlib = require('node:zlib');

const lib = require('../lib/tripcord.js');

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

// ustar builds a one-pass ustar archive of [name, data] pairs.
function ustar(files) {
  const blocks = [];
  for (const [name, data] of files) {
    const h = Buffer.alloc(512);
    h.write(name, 0, 'utf8');
    h.write('0000755\0', 100);
    h.write('0000000\0', 108);
    h.write('0000000\0', 116);
    h.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124);
    h.write('00000000000\0', 136);
    h.write('        ', 148);
    h.write('0', 156);
    h.write('ustar\0', 257);
    h.write('00', 263);
    let sum = 0;
    for (const b of h) sum += b;
    h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
    blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

// zipOf builds a zip of [name, data, method] entries (0 store, 8 deflate).
function zipOf(files) {
  const locals = [];
  const central = [];
  let off = 0;
  for (const [name, data, method] of files) {
    const body = method === 8 ? zlib.deflateRawSync(data) : data;
    const n = Buffer.from(name);
    const l = Buffer.alloc(30);
    l.writeUInt32LE(0x04034b50, 0);
    l.writeUInt16LE(20, 4);
    l.writeUInt16LE(method, 8);
    l.writeUInt32LE(body.length, 18);
    l.writeUInt32LE(data.length, 22);
    l.writeUInt16LE(n.length, 26);
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE(20, 4);
    c.writeUInt16LE(20, 6);
    c.writeUInt16LE(method, 10);
    c.writeUInt32LE(body.length, 20);
    c.writeUInt32LE(data.length, 24);
    c.writeUInt16LE(n.length, 28);
    c.writeUInt32LE(off, 42);
    locals.push(l, n, body);
    central.push(c, n);
    off += 30 + n.length + body.length;
  }
  const cd = Buffer.concat(central);
  const e = Buffer.alloc(22);
  e.writeUInt32LE(0x06054b50, 0);
  e.writeUInt16LE(files.length, 8);
  e.writeUInt16LE(files.length, 10);
  e.writeUInt32LE(cd.length, 12);
  e.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, e]);
}

test('target maps the six release platforms', () => {
  const cases = [
    ['linux', 'x64', 'linux', 'amd64', '.tar.gz', 'tripcord'],
    ['linux', 'arm64', 'linux', 'arm64', '.tar.gz', 'tripcord'],
    ['darwin', 'x64', 'darwin', 'amd64', '.tar.gz', 'tripcord'],
    ['darwin', 'arm64', 'darwin', 'arm64', '.tar.gz', 'tripcord'],
    ['win32', 'x64', 'windows', 'amd64', '.zip', 'tripcord.exe'],
    ['win32', 'arm64', 'windows', 'arm64', '.zip', 'tripcord.exe'],
  ];
  for (const [platform, arch, goos, goarch, ext, binary] of cases) {
    assert.deepEqual(lib.target(platform, arch), { goos, goarch, ext, binary });
  }
  assert.equal(lib.archiveName('0.1.0', lib.target('win32', 'arm64')), 'tripcord_0.1.0_windows_arm64.zip');
  assert.equal(
    lib.archiveURL('0.1.0', 'tripcord_0.1.0_linux_amd64.tar.gz'),
    'https://github.com/vgmartinez/tripcord/releases/download/v0.1.0/tripcord_0.1.0_linux_amd64.tar.gz',
  );
});

test('target rejects every other platform with a clear error', () => {
  for (const [platform, arch] of [
    ['freebsd', 'x64'],
    ['linux', 'ia32'],
    ['linux', 'arm'],
    ['aix', 'ppc64'],
    ['win32', 'ia32'],
    ['linux', 's390x'],
  ]) {
    assert.throws(() => lib.target(platform, arch), new RegExp(`no release binary for ${platform}/${arch}`));
  }
});

test('parseSums reads sha256sum output and rejects anything else', () => {
  const a = 'a'.repeat(64);
  const sums = lib.parseSums(`${a}  tripcord_0.1.0_linux_amd64.tar.gz\n`);
  assert.equal(sums.get('tripcord_0.1.0_linux_amd64.tar.gz'), a);
  for (const bad of [
    `${a}  x\n${a}  x\n`,
    `${a} x\n`,
    `${a.toUpperCase()}  x\n`,
    `${a}  x`,
    `${a.slice(1)}  x\n`,
  ]) {
    assert.throws(() => lib.parseSums(bad), /SHA256SUMS/);
  }
});

test('checkURL allows only https GitHub release hosts', () => {
  for (const ok of [
    'https://github.com/vgmartinez/tripcord/releases/download/v0.1.0/x',
    'https://release-assets.githubusercontent.com/github-production-release-asset/1/2?sig=x',
    'https://objects.githubusercontent.com/x',
  ]) {
    lib.checkURL(ok);
  }
  for (const bad of [
    'http://github.com/x',
    'https://github.com:8443/x',
    'https://evil.example/x',
    'https://github.com.evil.example/x',
    'https://raw.githubusercontent.com/x',
  ]) {
    assert.throws(() => lib.checkURL(bad), /refusing to download/);
  }
});

test('extract reads the binary from tar.gz and zip archives', () => {
  const bin = Buffer.from('#!/bin/sh\necho fake\n');
  const tgz = zlib.gzipSync(ustar([['tripcord', bin], ['LICENSE', Buffer.from('L')]]));
  assert.deepEqual(lib.extract(tgz, lib.target('linux', 'x64')), bin);
  for (const method of [0, 8]) {
    const zip = zipOf([['LICENSE', Buffer.from('L'), method], ['tripcord.exe', bin, method]]);
    assert.deepEqual(lib.extract(zip, lib.target('win32', 'x64')), bin);
  }
  assert.throws(() => lib.extract(zlib.gzipSync(ustar([['other', bin]])), lib.target('linux', 'x64')), /no tripcord/);
});

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tripcord-npm-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('ensureBinary verifies the download, caches it, and fails closed on a mismatch', async (t) => {
  const dir = fixture(t);
  const bin = Buffer.from('#!/bin/sh\necho "v9.8.7 (commit fake)"\n');
  const tgz = zlib.gzipSync(ustar([['tripcord', bin]]));
  const name = 'tripcord_9.8.7_linux_amd64.tar.gz';
  const fetched = [];
  const fetch = async (url) => {
    fetched.push(url);
    return tgz;
  };
  const base = { version: '9.8.7', platform: 'linux', arch: 'x64', fetch, log: () => {} };

  // A wrong digest: nothing is written and nothing is returned.
  const badDir = path.join(dir, 'bad');
  await assert.rejects(
    lib.ensureBinary({ ...base, cacheDir: badDir, sums: new Map([[name, 'b'.repeat(64)]]) }),
    /Refusing to run it/,
  );
  assert.equal(fs.existsSync(badDir), false);

  // No entry for this platform.
  await assert.rejects(lib.ensureBinary({ ...base, cacheDir: badDir, sums: new Map() }), /no entry for/);

  fetched.length = 0;
  const good = { ...base, cacheDir: path.join(dir, 'good'), sums: new Map([[name, sha(tgz)]]) };
  const p = await lib.ensureBinary(good);
  assert.deepEqual(fs.readFileSync(p), bin);
  if (process.platform !== 'win32') assert.equal(fs.statSync(p).mode & 0o777, 0o755);
  assert.deepEqual(fetched, [`https://github.com/vgmartinez/tripcord/releases/download/v9.8.7/${name}`]);

  // The second call is a cache hit: no fetch.
  assert.equal(await lib.ensureBinary(good), p);
  assert.equal(fetched.length, 1);

  // A different digest for the same version is not a cache hit, and a
  // bad download then fails without touching the cached binary.
  await assert.rejects(lib.ensureBinary({ ...good, sums: new Map([[name, 'c'.repeat(64)]]) }), /Refusing/);
  assert.deepEqual(fs.readFileSync(p), bin);
});

test('ensureBinary re-hashes the cached binary and re-downloads on a mismatch or old stamp', async (t) => {
  const dir = fixture(t);
  const bin = Buffer.from('#!/bin/sh\necho "v9.8.7 (commit fake)"\n');
  const tgz = zlib.gzipSync(ustar([['tripcord', bin]]));
  const name = 'tripcord_9.8.7_linux_amd64.tar.gz';
  const fetched = [];
  const fetch = async (url) => {
    fetched.push(url);
    return tgz;
  };
  const opts = {
    version: '9.8.7',
    platform: 'linux',
    arch: 'x64',
    fetch,
    log: () => {},
    cacheDir: path.join(dir, 'cache'),
    sums: new Map([[name, sha(tgz)]]),
  };

  const p = await lib.ensureBinary(opts);
  assert.deepEqual(fs.readFileSync(p), bin);
  assert.equal(fetched.length, 1);
  if (process.platform !== 'win32') {
    assert.equal(execFileSync(p, { encoding: 'utf8' }), 'v9.8.7 (commit fake)\n');
  }

  // Unchanged binary: a cache hit, no download, and the binary still runs.
  assert.equal(await lib.ensureBinary(opts), p);
  assert.equal(fetched.length, 1);
  if (process.platform !== 'win32') {
    assert.equal(execFileSync(p, { encoding: 'utf8' }), 'v9.8.7 (commit fake)\n');
  }

  // Flipping one byte of the cached binary is a miss: re-download,
  // re-verify, and run the fresh binary.
  const corrupted = Buffer.from(fs.readFileSync(p));
  corrupted[0] ^= 0xff;
  fs.writeFileSync(p, corrupted, { mode: 0o755 });
  const p2 = await lib.ensureBinary(opts);
  assert.equal(p2, p);
  assert.deepEqual(fs.readFileSync(p), bin);
  assert.equal(fetched.length, 2);
  if (process.platform !== 'win32') {
    assert.equal(execFileSync(p, { encoding: 'utf8' }), 'v9.8.7 (commit fake)\n');
  }

  // An old-format stamp (archive digest only) is a miss.
  const stamp = path.join(path.dirname(p), 'archive.sha256');
  fs.writeFileSync(stamp, `${sha(tgz)}\n`);
  assert.equal(await lib.ensureBinary(opts), p);
  assert.equal(fetched.length, 3);
  assert.deepEqual(fs.readFileSync(p), bin);
  // The stamp is rewritten in the two-digest format, so the next call hits.
  assert.equal(await lib.ensureBinary(opts), p);
  assert.equal(fetched.length, 3);
});

test('the unstaged development package refuses to run', async (t) => {
  const dir = fixture(t);
  fs.copyFileSync(path.join(__dirname, '..', 'package.json'), path.join(dir, 'package.json'));
  await assert.rejects(lib.ensureBinary({ pkgDir: dir, platform: 'linux', arch: 'x64' }), /development copy/);
});

test('cacheRoot follows the platform convention', () => {
  assert.equal(lib.cacheRoot({ TRIPCORD_CACHE_DIR: '/c' }, 'linux', '/h'), '/c');
  assert.equal(lib.cacheRoot({ XDG_CACHE_HOME: '/x' }, 'linux', '/h'), path.join('/x', 'tripcord'));
  assert.equal(lib.cacheRoot({}, 'linux', '/h'), path.join('/h', '.cache', 'tripcord'));
  assert.equal(lib.cacheRoot({}, 'darwin', '/h'), path.join('/h', 'Library', 'Caches', 'tripcord'));
  assert.equal(lib.cacheRoot({ LOCALAPPDATA: 'L' }, 'win32', '/h'), path.join('L', 'tripcord', 'cache'));
});

test('the package ships no install script and no dependencies', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.equal(pkg.name, 'tripcord');
  assert.equal(pkg.version, '0.0.0-dev');
  assert.equal(pkg.repository.url, 'git+https://github.com/vgmartinez/tripcord.git');
  for (const key of ['dependencies', 'optionalDependencies', 'peerDependencies']) assert.equal(pkg[key], undefined);
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) assert.equal(pkg.scripts[hook], undefined);
  const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'tripcord.js'), 'utf8');
  const required = [...src.matchAll(/require\('([^']+)'\)/g)].map((m) => m[1]);
  assert.ok(required.every((r) => r.startsWith('node:')), `non-built-in require: ${required}`);
});
