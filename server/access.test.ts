import { mkdtempSync, rmSync } from 'node:fs'
import { connect } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { startServer, type RunningServer } from './app.ts'
import { decodeTotpSecret, totpCounter } from './totp.ts'

// RFC 6238's SHA-1 test secret. The six-digit codes are the last six digits of its vectors.
const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
const password = 'test password'
const protectedPath = '/murmur/connections'
const cookie = (res: Response, name: string) => res.headers.getSetCookie().find((line) => line.startsWith(`${name}=`)) ?? ''
const value = (setCookie: string) => setCookie.split(';')[0]

it('validates RFC 6238 codes including a leading zero and one step of drift', () => {
  const key = decodeTotpSecret(secret.toLowerCase())
  expect(key.toString()).toBe('12345678901234567890')
  expect(totpCounter(key, '287082', 59_000)).toBe(1)
  expect(totpCounter(key, '287082', 60_000)).toBe(1)
  expect(totpCounter(key, '287082', 90_000)).toBeNull()
  expect(totpCounter(key, '081804', 1_111_111_109_000)).toBe(37_037_036)
  expect(totpCounter(key, '81804', 1_111_111_109_000)).toBeNull()
  expect(() => decodeTotpSecret('INVALID')).toThrow('Base32')
})

describe('Murmur sign-in', () => {
  let dir: string
  let app: RunningServer | undefined
  const start = async (env = { MURMUR_PASSWORD: password, MURMUR_TOTP_SECRET: secret }) => {
    app = await startServer({ host: '127.0.0.1', port: 0, dataDir: dir, env })
  }
  const request = (path: string, cookies = '', body?: object) => fetch(`${app!.url}${path}`, {
    method: body ? 'POST' : 'GET',
    headers: { cookie: cookies, 'content-type': 'application/json', 'x-forwarded-proto': 'https' },
    body: body && JSON.stringify(body),
  })
  const login = () => request('/murmur/login', '', { password })
  const verify = (challenge: string, code: string) => request('/murmur/login/totp', challenge, { code })
  const websocketStatus = (challenge: string) => new Promise<string>((resolve, reject) => {
    const socket = connect(app!.port, '127.0.0.1', () => {
      socket.write(`GET /hermes/api/ws HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nCookie: ${challenge}\r\n\r\n`)
    })
    socket.on('error', reject)
    socket.once('data', (data) => {
      socket.destroy()
      resolve(String(data).split('\r\n')[0])
    })
  })

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'murmur-access-'))
  })
  afterEach(async () => {
    vi.restoreAllMocks()
    await app?.close()
    app = undefined
    rmSync(dir, { recursive: true, force: true })
  })

  it('keeps apps without a password and existing password-only sign-in working', async () => {
    await start({ MURMUR_PASSWORD: '', MURMUR_TOTP_SECRET: '' })
    expect(await (await request('/murmur/session')).json()).toEqual({ required: false, signedIn: true })
    await app!.close()
    await start({ MURMUR_PASSWORD: password, MURMUR_TOTP_SECRET: '' })
    const loggedIn = await login()
    expect(await loggedIn.json()).toEqual({ ok: true })
    const oldSession = cookie(loggedIn, 'murmur_session')
    expect(oldSession).toContain('Max-Age=2592000')
    expect(await (await request('/murmur/session', value(oldSession))).json()).toEqual({ required: true, signedIn: true })
    await app!.close()
    await start()
    expect((await request(protectedPath, value(oldSession))).status).toBe(401)
  })

  it('requires both factors for HTTP and WebSockets, and revokes the completed session on logout', async () => {
    await start()
    vi.spyOn(Date, 'now').mockReturnValue(59_000)
    expect((await verify('', '287082')).status).toBe(401)
    const first = await login()
    expect(await first.json()).toEqual({ awaitingCode: true })
    expect(cookie(first, 'murmur_session')).toBe('')
    expect(cookie(first, 'murmur_login')).toContain('Max-Age=300; HttpOnly; SameSite=Lax; Secure')
    const challenge = value(cookie(first, 'murmur_login'))
    expect(await (await request('/murmur/session', challenge)).json()).toEqual({ required: true, signedIn: false, twoFactor: true, awaitingCode: true })
    expect((await request(protectedPath, challenge)).status).toBe(401)
    expect((await request('/hermes/api/sessions', challenge)).status).toBe(401)
    expect(await websocketStatus(challenge)).toBe('HTTP/1.1 401 Unauthorized')
    expect((await verify(challenge, '000000')).status).toBe(401)
    const result = await verify(challenge, '287082')
    expect(result.status).toBe(200)
    expect(cookie(result, 'murmur_session')).toContain('Max-Age=43200; HttpOnly; SameSite=Lax; Secure')
    const session = value(cookie(result, 'murmur_session'))
    expect(await (await request('/murmur/session', session)).json()).toEqual({ required: true, signedIn: true, twoFactor: true, awaitingCode: false })
    expect((await verify(challenge, '287082')).status).toBe(401)
    expect((await request('/murmur/logout', session, {})).status).toBe(200)
    expect((await request(protectedPath, session)).status).toBe(401)
  })

  it('rejects a replay after a restart, expires challenges, and caps guesses', async () => {
    await start()
    const now = vi.spyOn(Date, 'now').mockReturnValue(59_000)
    const challenge = async () => value(cookie(await login(), 'murmur_login'))
    const first = await challenge()
    const second = await challenge()
    const results = await Promise.all([verify(first, '287082'), verify(second, '287082')])
    expect(results.map((result) => result.status).sort()).toEqual([200, 401])
    const session = value(cookie(results.find((result) => result.ok)!, 'murmur_session'))
    await app!.close()
    await start()
    expect((await request(protectedPath, session)).status).toBe(401)
    expect((await verify(await challenge(), '287082')).status).toBe(401)

    const expired = await challenge()
    now.mockReturnValue(359_000)
    expect(await (await verify(expired, '000000')).json()).toMatchObject({ restart: true })

    const active = await challenge()
    for (let n = 0; n < 5; n++) {
      expect(await (await verify(active, '000000')).json()).toMatchObject({ restart: n === 4 })
    }
    const next = await challenge()
    for (let n = 0; n < 4; n++) expect((await verify(next, '000000')).status).toBe(401)
    expect((await verify(next, '000000')).status).toBe(429)
  })

  it('fails to start when the authenticator key has no password or cannot be decoded', () => {
    expect(() => startServer({ env: { MURMUR_TOTP_SECRET: secret } })).toThrow('requires MURMUR_PASSWORD')
    expect(() => startServer({ env: { MURMUR_PASSWORD: password, MURMUR_TOTP_SECRET: 'INVALID' } })).toThrow('Base32')
  })
})
