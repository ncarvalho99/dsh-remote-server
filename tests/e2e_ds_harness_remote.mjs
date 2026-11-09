// Optional end-to-end check with the real ds-harness-remote package (Host + Client runtimes)
// against a disposable relay on loopback. Nothing touches a real relay or real device identities.
//
//   DSH_REMOTE_PKG=<path to node_modules/ds-harness-remote> RELAY_PYTHON=<python with requirements> \
//     node tests/e2e_ds_harness_remote.mjs
//
// Verifies: Host online, Client connects over the relay, relay data sockets attached by both members,
// resume leases acknowledged, and the tunnel surviving a Host control-socket drop (recovery hello).
import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, openSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const pkg = process.env.DSH_REMOTE_PKG
const python = process.env.RELAY_PYTHON ?? 'python'
if (!pkg) throw new Error('Set DSH_REMOTE_PKG to the ds-harness-remote package directory.')
// The bundle imports DSH host packages (e.g. @deepseek-ai/dsh-client-connection) that DSH itself provides;
// resolve them from the DSH install when DSH_HOME_PACKAGES points at its node_modules.
if (process.env.DSH_HOME_PACKAGES) {
  const { register } = await import('node:module')
  const base = pathToFileURL(join(process.env.DSH_HOME_PACKAGES, 'noop.js')).href
  register('data:text/javascript,' + encodeURIComponent(`export async function resolve(s, c, n) {
    try { return await n(s, c) } catch (e) { if (s.startsWith('@deepseek-ai/')) return n(s, { ...c, parentURL: ${JSON.stringify(base)} }); throw e }
  }`))
}
const remote = await import(pathToFileURL(join(pkg, 'dist', 'index.js')).href)
const { HostPluginRuntime, ClientModeRuntime, ClientServerApi, IdentityStore, ServerCredentialStore, resolveConfig } = remote
const version = JSON.parse(readFileSync(join(pkg, 'package.json'), 'utf8')).version

const EMAIL = 'relay-e2e@example.invalid'
const PASSWORD = 'relay-e2e-password'
const tmp = mkdtempSync(join(tmpdir(), 'dsh-relay-e2e-'))
const sleep = ms => new Promise(r => setTimeout(r, ms))
const lines = []
const logger = name => Object.fromEntries(['debug', 'info', 'warn', 'error'].map(level => [level, (message, fields) => {
  lines.push(`${name} ${level} ${message} ${fields ? JSON.stringify(fields) : ''}`)
}]))

async function freePort() {
  return new Promise(res => { const s = createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)) }) })
}

async function waitFor(label, predicate, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) return
    await sleep(250)
  }
  throw new Error(`timed out waiting for ${label}`)
}

const env = { ...process.env, DSH_REMOTE_DB: join(tmp, 'relay.sqlite3'), DSH_REMOTE_TOKEN_PEPPER: `e2e-${Date.now()}` }
delete env.DSH_REMOTE_PUBLIC_URL
const init = spawnSync(python, ['init_user.py', EMAIL, PASSWORD], { cwd: root, env })
if (init.status !== 0) throw new Error(`init_user failed: ${init.stderr}`)
const port = await freePort()
const relayLog = join(tmp, 'relay.log')
const relay = spawn(python, ['-m', 'uvicorn', 'app:app', '--host', '127.0.0.1', '--port', String(port)],
  { cwd: root, env, stdio: ['ignore', openSync(relayLog, 'w'), openSync(relayLog, 'a')] })
const serverUrl = `http://127.0.0.1:${port}`
const relayText = () => readFileSync(relayLog, 'utf8')
let host, client
let failed = false
try {
  await waitFor('relay health', async () => (await fetch(`${serverUrl}/health`).catch(() => undefined))?.ok)
  const config = resolveConfig({ serverUrl, forceRelay: true, logLevel: 'debug', codex: { enabled: false }, acp: { enabled: false } }, {})

  // A carrier-capable stub gateway makes the Host advertise harness.remote.*, so the Client keeps the connection.
  const hostGateway = { supportsCarrier: true, async invoke() { return { ok: false, error: { code: 'UNAVAILABLE', message: 'e2e stub', details: {} } } } }
  host = new HostPluginRuntime(config, new IdentityStore({ directory: join(tmp, 'host') }), logger('host'), hostGateway)
  await host.start()
  await host.authorizeHostWithAccount(EMAIL, PASSWORD)
  await waitFor('host online', () => /host \w+ online \(v[^,]+, attach=True, resume=True/.test(relayText()))
  console.log(`PASS ds-harness-remote ${version} Host online with relay attach + resume negotiated`)

  const clientIds = new IdentityStore({ directory: join(tmp, 'client') })
  const server = new ClientServerApi(serverUrl, new ServerCredentialStore(join(tmp, 'client-creds')))
  const unavailable = { ok: false, error: { code: 'UNAVAILABLE', message: 'e2e stub', details: {} } }
  // dispatchRpc + openWireStream make the local gateway carrier-capable (required for remote mode).
  const gatewayStub = { async invoke() { return unavailable }, async dispatchRpc() { return unavailable },
    async openWireStream() { return (async function* () {})() } }
  client = new ClientModeRuntime(config, clientIds, server, gatewayStub, logger('client'))
  await client.start()
  await client.authorizeClientWithAccount(EMAIL, PASSWORD)
  const devices = await client.devices()
  const target = devices.find(d => d.online) ?? devices[0]
  if (!target) throw new Error('client sees no Host')
  await client.setMode('remote', target.deviceId).catch(error => lines.push(`client setMode: ${error.message}`))
  await waitFor('client connected', () => client.status().connected === true, 45000)
  const status = client.status()
  console.log(`PASS Client connected to Host over ${status.transport}`)
  await waitFor('both data sockets', () => (relayText().match(/data socket attached/g) ?? []).length >= 2)
  console.log('PASS both members attached relay data sockets')

  // Leases start once the secure channel is ready; the first request is immediate.
  await waitFor('lease ack', () => lines.some(l => /lease/i.test(l)) || true, 1000)
  const conn = host.serverConnection
  await waitFor('host lease confirmed', () => [...conn.tunnels.values()].some(t => t.lease?.canDetach()), 15000)
  console.log('PASS Host relay lease confirmed by the relay')

  conn.socket?.close(1000, 'e2e control drop')
  await waitFor('recovery hello', () => /recovered=1\)/.test(relayText()), 45000)
  if (/control closed|reconnected without it/.test(relayText())) throw new Error('tunnel was torn down during Host control drop')
  await sleep(1000)
  if (client.status().connected !== true) throw new Error('client lost the connection across the Host control drop')
  console.log('PASS tunnel survived a Host control drop and resumed with recoveryTickets')
} catch (error) {
  failed = true
  console.error('FAIL', error.message)
  console.error('--- relay log ---\n' + relayText().split('\n').filter(l => !/GET \/health/.test(l)).slice(-60).join('\n'))
  console.error('--- runtime log ---\n' + lines.slice(-60).join('\n'))
} finally {
  await client?.close?.().catch?.(() => undefined)
  await host?.stop?.().catch?.(() => undefined)
  relay.kill()
  await sleep(500)
  rmSync(tmp, { recursive: true, force: true, maxRetries: 5 })
}
if (failed) process.exit(1)
console.log('ALL PASS')
process.exit(0)
