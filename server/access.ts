// Murmur's own sign-in, for standalone installs. Static files stay public so
// the browser can show the sign-in screen. Settings and Hermes need a session.
// On umbrelOS the app proxy handles the Umbrel account's sign-in (and its 2FA).

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type http from 'node:http'
import { consumeTotp, memo, sessionSecret, setting } from './config.ts'
import { appendCookie, readCookie, readJson, secure, sendJson } from './http.ts'
import { decodeTotpSecret, totpCounter } from './totp.ts'

const COOKIE = 'murmur_session'
const CHALLENGE_COOKIE = 'murmur_login'
const MAX_AGE_S = 30 * 24 * 60 * 60
const TOTP_MAX_AGE_S = 12 * 60 * 60
const CHALLENGE_AGE_S = 5 * 60
const WINDOW_MS = 10 * 60_000
const MAX_ATTEMPTS = 10
const MAX_CODE_ATTEMPTS = 5

const sha = (value: string | Buffer) => createHash('sha256').update(value).digest()
export const totpConfig = memo(() => {
  const value = setting('MURMUR_TOTP_SECRET')
  if (!value) return null
  if (!setting('MURMUR_PASSWORD')) throw new Error('MURMUR_TOTP_SECRET requires MURMUR_PASSWORD.')
  const secret = decodeTotpSecret(value)
  return { secret, keyId: sha(secret).toString('hex') }
})

// A password change invalidates its signed cookies. Authenticator sessions live in memory.
const gate = memo(() => {
  const password = setting('MURMUR_PASSWORD')
  if (!password) return null
  const totp = totpConfig()
  return {
    password,
    key: totp ? null : createHmac('sha256', sessionSecret()).update(`murmur-session\0${password}`).digest(),
    totp,
    sessions: new Map<string, number>(),
    challenges: new Map<string, { expires: number; tries: number }>(),
    attempts: new Map<string, number[]>(),
    codeAttempts: new Map<string, number[]>(),
  }
})
const signedOut = new Set<(session: string) => void>()

export const accessRequired = () => Boolean(gate())

const sign = (key: Buffer, payload: string) => createHmac('sha256', key).update(payload).digest('base64url')

/** Called with the sign-in being ended, so sockets it opened can be closed. Returns a function that stops calling it. */
export function onSignOut(fn: (session: string) => void) {
  signedOut.add(fn)
  return () => void signedOut.delete(fn)
}

/** This request's sign-in (its cookie), or null without one. */
export const cookieValue = (req: http.IncomingMessage) => readCookie(req, COOKIE)

/** Expiry for an authenticator session, so it applies to already-open sockets too. */
export const authSessionExpiry = (session: string) => gate()?.sessions.get(session)

/** True when the request may reach Hermes. */
export function isSignedIn(req: http.IncomingMessage) {
  const access = gate()
  if (!access) return true
  const cookie = cookieValue(req) ?? ''
  if (!access.key) return (access.sessions.get(cookie) ?? 0) > Date.now()
  const [expires, mac, ...extra] = cookie.split('.')
  if (!expires || !mac || !/^\d+$/.test(expires) || Number(expires) <= Date.now() || extra.length) return false
  const expected = Buffer.from(sign(access.key, expires))
  const given = Buffer.from(mac)
  return given.length === expected.length && timingSafeEqual(given, expected)
}

function setCookie(req: http.IncomingMessage, name: string, value: string, maxAge: number) {
  return `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${secure(req) ? '; Secure' : ''}`
}

function rateLimited(attempts: Map<string, number[]>, ip: string) {
  const now = Date.now()
  if (attempts.size >= 1024) {
    for (const [address, times] of attempts) if (now - times[times.length - 1] >= WINDOW_MS) attempts.delete(address)
    if (attempts.size >= 1024 && !attempts.has(ip)) return WINDOW_MS / 1000
  }
  const recent = (attempts.get(ip) ?? []).filter((t) => now - t < WINDOW_MS)
  attempts.set(ip, recent)
  if (recent.length >= MAX_ATTEMPTS) return Math.ceil((recent[0] + WINDOW_MS - now) / 1000)
  recent.push(now)
  return 0
}

function tooMany(res: http.ServerResponse, wait: number) {
  res.setHeader('retry-after', String(wait))
  sendJson(res, 429, { error: 'Too many tries. Wait a few minutes, then try again.' })
}

function finishSignIn(req: http.IncomingMessage, res: http.ServerResponse, access: NonNullable<ReturnType<typeof gate>>) {
  const now = Date.now()
  const age = access.key ? MAX_AGE_S : TOTP_MAX_AGE_S
  const expires = now + age * 1000
  let value: string
  if (access.key) {
    value = `${expires}.${sign(access.key, String(expires))}`
  } else {
    for (const [session, end] of access.sessions) if (end <= now) access.sessions.delete(session)
    value = randomBytes(32).toString('base64url')
    access.sessions.set(value, expires)
  }
  appendCookie(res, setCookie(req, COOKIE, value, age))
  sendJson(res, 200, { ok: true })
}

/** Handles Murmur's session, password, authenticator, and sign-out endpoints. */
export async function handleAccess(req: http.IncomingMessage, res: http.ServerResponse, path: string) {
  const access = gate()
  const id = readCookie(req, CHALLENGE_COOKIE) ?? ''
  const challenge = access?.challenges.get(id)
  if (path === '/murmur/session' && req.method === 'GET') {
    const signedIn = isSignedIn(req)
    sendJson(res, 200, {
      required: Boolean(access),
      signedIn,
      ...(access?.totp && { twoFactor: true, awaitingCode: !signedIn && !!challenge && challenge.expires > Date.now() }),
    })
    return true
  }
  if (path === '/murmur/logout' && req.method === 'POST') {
    access?.challenges.delete(id)
    appendCookie(res, setCookie(req, COOKIE, '', 0))
    appendCookie(res, setCookie(req, CHALLENGE_COOKIE, '', 0))
    const session = cookieValue(req)
    if (session) {
      access?.sessions.delete(session)
      for (const fn of signedOut) fn(session)
    }
    sendJson(res, 200, { ok: true })
    return true
  }
  const verify = path === '/murmur/login/totp'
  if (req.method !== 'POST' || (!verify && path !== '/murmur/login')) return false
  if (!access) {
    sendJson(res, verify ? 404 : 200, verify ? { error: 'not_found' } : { ok: true })
    return true
  }
  const ip = req.socket.remoteAddress ?? ''
  if (verify) {
    const body = (await readJson(req).catch(() => null)) as { code?: unknown } | null
    if (!access.totp || !challenge || challenge.expires <= Date.now() || !access.challenges.has(id)) {
      access.challenges.delete(id)
      appendCookie(res, setCookie(req, CHALLENGE_COOKIE, '', 0))
      sendJson(res, 401, { error: 'Sign in with your password again to get a new attempt.', restart: true })
      return true
    }
    const wait = rateLimited(access.codeAttempts, ip)
    if (wait) {
      tooMany(res, wait)
      return true
    }
    const counter = totpCounter(access.totp.secret, body?.code)
    if (counter !== null && consumeTotp(access.totp.keyId, counter)) {
      access.challenges.delete(id)
      appendCookie(res, setCookie(req, CHALLENGE_COOKIE, '', 0))
      finishSignIn(req, res, access)
      return true
    }
    const restart = ++challenge.tries >= MAX_CODE_ATTEMPTS
    if (restart) {
      access.challenges.delete(id)
      appendCookie(res, setCookie(req, CHALLENGE_COOKIE, '', 0))
    }
    sendJson(res, 401, { error: restart ? 'Sign in again and use a fresh code.' : 'That code didn’t work. Try a fresh code.', restart })
    return true
  }

  const wait = rateLimited(access.attempts, ip)
  if (wait) {
    tooMany(res, wait)
    return true
  }
  const body = (await readJson(req).catch(() => null)) as { password?: unknown } | null
  const given = typeof body?.password === 'string' ? body.password : ''
  // Compare digests so neither the length nor the content leaks through timing.
  if (!timingSafeEqual(sha(given), sha(access.password))) {
    await new Promise((r) => setTimeout(r, 400))
    sendJson(res, 401, { error: 'That password didn’t work.' })
    return true
  }
  access.attempts.delete(ip)
  if (access.totp) {
    const now = Date.now()
    for (const [key, value] of access.challenges) if (value.expires <= now) access.challenges.delete(key)
    access.challenges.delete(id)
    if (access.challenges.size >= 1024) {
      tooMany(res, CHALLENGE_AGE_S)
      return true
    }
    const token = randomBytes(32).toString('base64url')
    access.challenges.set(token, { expires: now + CHALLENGE_AGE_S * 1000, tries: 0 })
    appendCookie(res, setCookie(req, CHALLENGE_COOKIE, token, CHALLENGE_AGE_S))
    sendJson(res, 200, { awaitingCode: true })
    return true
  }
  finishSignIn(req, res, access)
  return true
}
