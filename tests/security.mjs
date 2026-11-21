// Security checks against a throwaway server (no real keys, no engines, no computer).
// Usage: npm run build -w server && node tests/security.mjs
// Starts server/dist/index.js on a free port with made-up keys and a database in a temp folder,
// restarting it with different settings (local app, public URL, allowlist on and off).
// Nothing is sent off this machine: Composio and Hermes point at a closed local port. A few steps
// have the server listen on this machine's network address for a moment, to act as another device.
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

const ROOT = path.resolve(new URL('.', import.meta.url).pathname, '..');
const ENTRY = path.join(ROOT, 'server/dist/index.js');
if (!fs.existsSync(ENTRY)) throw new Error('server/dist/index.js is missing: run `npm run build -w server` first');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'bothq-security-'));
const SECRET = crypto.randomBytes(32).toString('hex');
const PUBLIC_URL = 'https://hq.example.test';

const results = [];
const step = async (name, fn) => {
  try {
    await fn();
    results.push({ name, ok: true });
    console.log(`PASS ${name}`);
  } catch (e) {
    const why = String(e?.message ?? e).split('\n')[0];
    if (e?.skip) { results.push({ name, ok: true, skipped: true }); console.log(`SKIP ${name}: ${why}`); return; }
    results.push({ name, ok: false, error: why });
    console.log(`FAIL ${name}: ${why}`);
  }
};
const skip = (why) => { throw Object.assign(new Error(why), { skip: true }); };
const eq = (got, want, what) => { if (got !== want) throw new Error(`${what}: expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`); };

const freePort = () => new Promise((resolve, reject) => {
  const s = net.createServer();
  s.once('error', reject);
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});
const PORT = await freePort();
const DEAD = 'http://127.0.0.1:9'; // nothing listens on the discard port
const BASE = `http://127.0.0.1:${PORT}`;
// An address of this machine that is not loopback, to stand in for "another device" (none = those steps are skipped).
const nics = Object.entries(os.networkInterfaces()).flatMap(([name, list]) => (list ?? []).filter((i) => !i.internal && i.family === 'IPv4').map((i) => ({ name, address: i.address })));
const LAN_IP = (nics.find((i) => !/^(u?tun|tap)/.test(i.name)) ?? nics[0])?.address ?? null;
const LAN = LAN_IP ? `http://${LAN_IP}:${PORT}` : null;
const needLan = () => LAN ?? skip('this machine has no network address besides loopback');

// ---------- the server under test ----------

let child = null;
let log = '';
/** Hosts the server tried to reach outside this machine, over all its runs (each attempt was blocked). */
const blocked = new Set();
/** (Re)start the server with these settings on top of the throwaway defaults. `reach` is where to wait for it. */
async function start(extra, reach = BASE) {
  await stop();
  log = '';
  // no-outbound.mjs fails any connection the server makes to another machine and names it on stderr.
  child = spawn(process.execPath, ['--import', path.join(ROOT, 'tests/no-outbound.mjs'), ENTRY], {
    cwd: path.join(ROOT, 'server'),
    stdio: ['ignore', 'pipe', 'pipe'],
    // A clean environment: none of the caller's keys, and HOME in the temp folder so no real Hermes home is read.
    env: {
      PATH: process.env.PATH ?? '', HOME: TMP, NODE_ENV: 'test', TELEMETRY_DISABLED: 'true',
      PORT: String(PORT), HOST: '127.0.0.1', SESSION_SECRET: SECRET, DB_PATH: path.join(TMP, 'hq.db'),
      XAI_API_KEY: 'test-not-a-key', COMPOSIO_API_KEY: 'test-not-a-key', COMPOSIO_BASE_URL: DEAD, ORGO_API_KEY: 'test-not-a-key',
      HERMES_URL: DEAD, HERMES_HOME_PRIMARY: path.join(TMP, 'hermes'), HERMES_BIN: path.join(TMP, 'no-hermes'),
      ENGINES_DIR: path.join(TMP, 'engines'), ENGINE_PORT_BASE: String(PORT + 1), MAX_BOTS: '20', BOTHQ_NO_SCHEDULER: '1',
      ...extra,
    },
  });
  child.stdout.on('data', (d) => { log += d; });
  child.stderr.on('data', (d) => { log += d; for (const m of String(d).matchAll(/\[no-outbound\] blocked a connection to (\S+)/g)) blocked.add(m[1]); });
  const mine = child;
  for (let i = 0; i < 100; i++) {
    if (mine.exitCode !== null) break;
    try { if ((await fetch(`${reach}/api/health`)).ok) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`server did not start:\n${log}`);
}
async function stop() {
  if (!child) return;
  const c = child;
  child = null;
  if (c.exitCode === null) { c.kill('SIGTERM'); await new Promise((r) => c.once('exit', r)); }
}
const LOCAL = { APP_URL: 'http://localhost:5173', SERVER_URL: BASE, DEV_LOGIN: '1' };
const PUBLIC = { APP_URL: PUBLIC_URL, SERVER_URL: PUBLIC_URL, DEV_LOGIN: '0' };

// ---------- requests ----------

const req = (p, { cookie, headers, body, method, base = BASE } = {}) => fetch(`${base}${p}`, {
  method: method ?? (body === undefined ? 'GET' : 'POST'),
  redirect: 'manual',
  headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(cookie ? { cookie: `bothq_session=${cookie}` } : {}), ...(headers ?? {}) },
  body: body === undefined ? undefined : JSON.stringify(body),
});
/** Passes when nothing listens at `url`. */
async function refused(url) {
  try { await fetch(url, { signal: AbortSignal.timeout(3000) }); } catch (e) {
    if (e?.cause?.code === 'ECONNREFUSED') return;
    throw new Error(`expected ${url} to refuse the connection, got ${e?.cause?.code ?? e}`);
  }
  throw new Error(`${url} answered`);
}
const sessionOf = (res) => (res.headers.get('set-cookie') ?? '').match(/bothq_session=([^;]+)/)?.[1];
const me = async (cookie) => (await (await req('/api/auth/me', { cookie })).json()).user?.email ?? null;
const OWNER_KEY = crypto.createHmac('sha256', SECRET).update('owner-login').digest('hex');
const asOwner = { authorization: `Bearer ${OWNER_KEY}` };

async function devLogin(email) {
  const res = await req('/api/auth/dev', { body: { email } });
  const cookie = sessionOf(res);
  if (!cookie) throw new Error(`dev login failed for ${email}: ${res.status}`);
  return cookie;
}

// ---------- A: the allowlist holds for accounts and sessions that already exist ----------

const STALE = 'stale@example.test';   // signed up while the app was open, never on the list
const LISTED = 'listed@example.test'; // on the list
const GUEST = 'guest@example.test';   // let in with the owner key, never on the list
const cookies = {};

try {
  await start(LOCAL);
  await step('local app: anyone signs in and stays signed in (empty list)', async () => {
    cookies.stale = await devLogin(STALE);
    cookies.listed = await devLogin(LISTED);
    eq(await me(cookies.stale), STALE, 'stale session');
    eq(await me(cookies.listed), LISTED, 'listed session');
  });

  await start({ ...PUBLIC, ALLOWED_EMAILS: `Listed@Example.test` });
  await step('public URL: a session whose address is not on the list is signed out', async () => {
    eq(await me(cookies.stale), null, '/api/auth/me');
    eq((await req('/api/bots', { cookie: cookies.stale })).status, 401, '/api/bots');
  });
  await step('public URL: a session whose address is on the list keeps working', async () => {
    eq(await me(cookies.listed), LISTED, '/api/auth/me');
    eq((await req('/api/bots', { cookie: cookies.listed })).status, 200, '/api/bots');
  });
  await step('public URL: the owner key signs in an address that is not on the list', async () => {
    const res = await req('/api/auth/owner', { headers: asOwner, body: { email: GUEST } });
    eq(res.status, 200, 'owner sign-in');
    cookies.guest = sessionOf(res);
    eq(await me(cookies.guest), GUEST, 'guest session');
    eq((await req('/api/bots', { cookie: cookies.guest })).status, 200, '/api/bots');
  });
  await step('public URL: an owner sign-in link works the same, once', async () => {
    const made = await (await req('/api/auth/owner', { headers: asOwner, body: { email: STALE, link: true } })).json();
    const linkPath = new URL(made.url).pathname;
    const res = await req(linkPath);
    cookies.staleByOwner = sessionOf(res);
    eq(await me(cookies.staleByOwner), STALE, 'session from the link');
    eq((await req(linkPath)).status, 410, 'second use of the link');
    // The owner vouched for that browser only: the old cookie stays refused.
    eq(await me(cookies.stale), null, 'the earlier session');
  });

  await start({ ...PUBLIC, ALLOWED_EMAILS: '' });
  await step('public URL, empty list: earlier accounts are signed out, owner sessions are kept', async () => {
    eq(await me(cookies.stale), null, 'stale session');
    eq(await me(cookies.listed), null, 'listed session');
    eq(await me(cookies.guest), GUEST, 'owner session');
    eq(await me(cookies.staleByOwner), STALE, 'owner link session');
    eq((await req('/api/auth/dev', { body: { email: LISTED } })).status, 403, 'dev login on a public URL');
  });

  await start(LOCAL);
  await step('local app again: every session works as before', async () => {
    eq(await me(cookies.stale), STALE, 'stale session');
    eq(await me(cookies.listed), LISTED, 'listed session');
  });

  // ---------- B: a local app listens on this machine only ----------

  await start({ ...LOCAL, HOST: undefined });
  await step('local app, HOST unset: listens on 127.0.0.1 and answers as localhost', async () => {
    eq((await fetch(`http://localhost:${PORT}/api/health`)).status, 200, 'http://localhost');
    if (!log.includes('listening on 127.0.0.1')) throw new Error(`start-up line does not name 127.0.0.1: ${log.split('\n').find((l) => l.includes('[bothq] server')) ?? '(none)'}`);
  });
  await step('local app, HOST unset: not offered on the network address', async () => refused(`${needLan()}/api/health`));
  if (LAN) await start({ ...LOCAL, HOST: LAN_IP }, LAN);
  await step('HOST set: the server listens there instead', async () => {
    eq((await fetch(`${needLan()}/api/health`)).status, 200, 'network address');
    await refused(`${BASE}/api/health`);
  });
  if (LAN) await start({ ...PUBLIC, ALLOWED_EMAILS: LISTED, HOST: undefined });
  await step('public URL, HOST unset: still every interface', async () => {
    eq((await fetch(`${needLan()}/api/health`)).status, 200, 'network address');
    eq((await fetch(`${BASE}/api/health`)).status, 200, 'loopback');
  });
} finally {
  await stop();
  fs.rmSync(TMP, { recursive: true, force: true });
}

await step('the server reached for nothing outside this machine but the Composio SDK\'s version check', async () => {
  eq([...blocked].filter((h) => h !== 'registry.npmjs.org').join(', '), '', 'other hosts it tried (all blocked)');
});
console.log(`   blocked outbound connections: ${[...blocked].join(', ') || 'none'}`);

const failed = results.filter((r) => !r.ok).length;
const skipped = results.filter((r) => r.skipped).length;
console.log(`\n${results.length - failed - skipped} passed, ${failed} failed, ${skipped} skipped.`);
if (failed && log) console.log(`--- last server log ---\n${log}`);
process.exit(failed ? 1 : 0);
