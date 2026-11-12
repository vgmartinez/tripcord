'use strict';

// Finds, downloads, verifies, and caches the tripcord release binary for
// this platform. Node built-ins only. The one network request is the
// release archive from github.com, which GitHub redirects to
// release-assets.githubusercontent.com (formerly
// objects.githubusercontent.com). Nothing runs until the archive's
// sha256 matches the SHA256SUMS that ships in this package.

const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');

const REPO = 'vgmartinez/tripcord';
const DEV_VERSION = '0.0.0-dev';
const MAX_ARCHIVE = 256 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 60 * 1000;
const ALLOWED_HOSTS = new Set([
  'github.com',
  'release-assets.githubusercontent.com',
  'objects.githubusercontent.com',
]);

const PLATFORMS = { darwin: 'darwin', linux: 'linux', win32: 'windows' };
const ARCHES = { x64: 'amd64', arm64: 'arm64' };

// target maps a Node platform and arch to a release archive target, or
// throws for anything the release does not build.
function target(platform, arch) {
  const goos = PLATFORMS[platform];
  const goarch = ARCHES[arch];
  if (!goos || !goarch) {
    throw new Error(
      `tripcord: no release binary for ${platform}/${arch}. ` +
        'Supported: linux, darwin, and win32 on x64 and arm64. ' +
        `See https://github.com/${REPO}#install for other ways to install.`,
    );
  }
  const windows = goos === 'windows';
  return {
    goos,
    goarch,
    ext: windows ? '.zip' : '.tar.gz',
    binary: windows ? 'tripcord.exe' : 'tripcord',
  };
}

function archiveName(version, t) {
  return `tripcord_${version}_${t.goos}_${t.goarch}${t.ext}`;
}

function archiveURL(version, name) {
  return `https://github.com/${REPO}/releases/download/v${version}/${name}`;
}

// parseSums reads a SHA256SUMS file as sha256sum writes it.
function parseSums(text) {
  const sums = new Map();
  if (!text.endsWith('\n')) throw new Error('tripcord: SHA256SUMS does not end in a newline');
  for (const line of text.slice(0, -1).split('\n')) {
    const m = /^([0-9a-f]{64}) {2}(\S+)$/.exec(line);
    if (!m) throw new Error(`tripcord: malformed SHA256SUMS line ${JSON.stringify(line)}`);
    if (sums.has(m[2])) throw new Error(`tripcord: SHA256SUMS lists ${m[2]} twice`);
    sums.set(m[2], m[1]);
  }
  return sums;
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// verify throws unless buf's sha256 is want.
function verify(buf, want, name) {
  const got = sha256(buf);
  if (got !== want) {
    throw new Error(
      `tripcord: ${name} has sha256 ${got}, but SHA256SUMS says ${want}. ` +
        'Refusing to run it.',
    );
  }
}

// checkURL throws unless url is https on a GitHub release host.
function checkURL(url) {
  const u = new URL(url);
  if (u.protocol !== 'https:' || !ALLOWED_HOSTS.has(u.hostname) || u.port !== '') {
    throw new Error(`tripcord: refusing to download from ${u.protocol}//${u.host}`);
  }
  return u;
}

// download fetches url over https, following at most MAX_REDIRECTS
// redirects, each to an allowed host.
function download(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    let u;
    try {
      u = checkURL(url);
    } catch (err) {
      reject(err);
      return;
    }
    const req = https.get(u, { headers: { 'user-agent': 'tripcord-npm' } }, (res) => {
      const status = res.statusCode || 0;
      if ([301, 302, 303, 307, 308].includes(status)) {
        res.resume();
        if (redirects >= MAX_REDIRECTS) {
          reject(new Error('tripcord: too many redirects'));
          return;
        }
        if (!res.headers.location) {
          reject(new Error('tripcord: redirect without a location'));
          return;
        }
        resolve(download(new URL(res.headers.location, u).toString(), redirects + 1));
        return;
      }
      if (status !== 200) {
        res.resume();
        reject(new Error(`tripcord: GET ${u.origin}${u.pathname} returned HTTP ${status}`));
        return;
      }
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_ARCHIVE) {
          req.destroy(new Error('tripcord: download is too large'));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error('tripcord: download timed out')));
    req.on('error', reject);
  });
}

function octal(buf, start, len) {
  const s = buf.toString('latin1', start, start + len).replace(/[\0 ]+$/, '').trim();
  return s === '' ? 0 : parseInt(s, 8);
}

// extractTar returns the regular file name from an uncompressed ustar
// archive.
function extractTar(tar, name) {
  let off = 0;
  while (off + 512 <= tar.length) {
    const header = tar.subarray(off, off + 512);
    if (header.every((b) => b === 0)) break;
    const field = (s, l) => header.toString('utf8', s, s + l).replace(/\0.*$/s, '');
    const prefix = field(345, 155);
    const entry = prefix ? `${prefix}/${field(0, 100)}` : field(0, 100);
    const size = octal(header, 124, 12);
    const type = String.fromCharCode(header[156]);
    const start = off + 512;
    if (start + size > tar.length) throw new Error('tripcord: truncated tar archive');
    if (entry === name && (type === '0' || type === '\0')) {
      return Buffer.from(tar.subarray(start, start + size));
    }
    off = start + Math.ceil(size / 512) * 512;
  }
  throw new Error(`tripcord: archive has no ${name}`);
}

// extractZip returns the file name from a zip archive (stored or
// deflated).
function extractZip(zip, name) {
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 22 - 0xffff); i--) {
    if (zip.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('tripcord: not a zip archive');
  const count = zip.readUInt16LE(eocd + 10);
  let off = zip.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (zip.readUInt32LE(off) !== 0x02014b50) throw new Error('tripcord: bad zip central directory');
    const method = zip.readUInt16LE(off + 10);
    const csize = zip.readUInt32LE(off + 20);
    const usize = zip.readUInt32LE(off + 24);
    const nlen = zip.readUInt16LE(off + 28);
    const elen = zip.readUInt16LE(off + 30);
    const clen = zip.readUInt16LE(off + 32);
    const local = zip.readUInt32LE(off + 42);
    const entry = zip.toString('utf8', off + 46, off + 46 + nlen);
    off += 46 + nlen + elen + clen;
    if (entry !== name) continue;
    if (zip.readUInt32LE(local) !== 0x04034b50) throw new Error('tripcord: bad zip local header');
    const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
    const data = zip.subarray(start, start + csize);
    let out;
    if (method === 0) out = Buffer.from(data);
    else if (method === 8) out = zlib.inflateRawSync(data);
    else throw new Error(`tripcord: unsupported zip method ${method}`);
    if (out.length !== usize) throw new Error(`tripcord: ${name} has the wrong size`);
    return out;
  }
  throw new Error(`tripcord: archive has no ${name}`);
}

function extract(archive, t) {
  if (t.ext === '.zip') return extractZip(archive, t.binary);
  return extractTar(zlib.gunzipSync(archive), t.binary);
}

function cacheRoot(env = process.env, platform = process.platform, home = os.homedir()) {
  if (env.TRIPCORD_CACHE_DIR) return env.TRIPCORD_CACHE_DIR;
  if (platform === 'win32') {
    return path.join(env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'tripcord', 'cache');
  }
  if (platform === 'darwin') return path.join(home, 'Library', 'Caches', 'tripcord');
  return path.join(env.XDG_CACHE_HOME || path.join(home, '.cache'), 'tripcord');
}

function readPackage(dir) {
  const version = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version;
  if (version === DEV_VERSION) {
    throw new Error(
      'tripcord: this is the unpublished development copy of the npm package; ' +
        'install tripcord from npm instead.',
    );
  }
  const sums = parseSums(fs.readFileSync(path.join(dir, 'SHA256SUMS'), 'utf8'));
  return { version, sums };
}

// ensureBinary returns the path of a verified binary for this platform,
// downloading it on first use. fetch is injectable for tests.
async function ensureBinary(opts = {}) {
  const pkgDir = opts.pkgDir || path.join(__dirname, '..');
  const t = target(opts.platform || process.platform, opts.arch || process.arch);
  const { version, sums } = opts.version ? opts : readPackage(pkgDir);
  const name = archiveName(version, t);
  const want = sums.get(name);
  if (!want) throw new Error(`tripcord: SHA256SUMS has no entry for ${name}`);
  const dir = path.join(opts.cacheDir || cacheRoot(), 'npm', version, `${t.goos}_${t.goarch}`);
  const bin = path.join(dir, t.binary);
  const stamp = path.join(dir, 'archive.sha256');
  if (cachedBinary(stamp, bin, want)) return bin;
  const log = opts.log || ((msg) => process.stderr.write(`${msg}\n`));
  log(`tripcord: downloading ${name} (first run of ${version})`);
  const archive = await (opts.fetch || download)(archiveURL(version, name));
  verify(archive, want, name);
  const data = extract(archive, t);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = path.join(dir, `.${t.binary}.${process.pid}.${crypto.randomBytes(6).toString('hex')}`);
  try {
    fs.writeFileSync(tmp, data, { mode: 0o755 });
    fs.renameSync(tmp, bin);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
  // The stamp records the archive digest and the sha256 of the extracted
  // binary. An old stamp that only has the archive digest is treated as
  // a miss, so the next run re-downloads and writes this format.
  fs.writeFileSync(stamp, `${want}\n${sha256(fs.readFileSync(bin))}\n`);
  return bin;
}

// cachedBinary is true when the stamp is the new two-digest format, the
// archive digest matches want, and a fresh sha256 of the cached binary
// matches the stored binary digest. A missing file, an old-format stamp,
// or any mismatch is a cache miss: the caller re-downloads.
function cachedBinary(stamp, bin, want) {
  try {
    if (!fs.statSync(bin).isFile()) return false;
    const text = fs.readFileSync(stamp, 'utf8');
    const first = text.indexOf('\n');
    if (first < 0 || text.slice(0, first) !== want) return false;
    const rest = text.slice(first + 1);
    const second = rest.indexOf('\n');
    if (second < 0 || rest.slice(second + 1) !== '') return false;
    const wantBin = rest.slice(0, second);
    if (!/^[0-9a-f]{64}$/.test(wantBin)) return false;
    return sha256(fs.readFileSync(bin)) === wantBin;
  } catch {
    return false;
  }
}

module.exports = {
  ALLOWED_HOSTS,
  archiveName,
  archiveURL,
  cacheRoot,
  checkURL,
  ensureBinary,
  extract,
  extractTar,
  extractZip,
  parseSums,
  target,
  verify,
};
