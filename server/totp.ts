import { createHmac, timingSafeEqual } from 'node:crypto'

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const STEP_MS = 30_000

export function decodeTotpSecret(value: string) {
  const secret = value.toUpperCase()
  if (!/^[A-Z2-7]{32,128}$/.test(secret)) throw new Error('MURMUR_TOTP_SECRET must be an unpadded Base32 key of at least 20 bytes.')
  const bytes = Buffer.alloc(Math.floor((secret.length * 5) / 8))
  if (Math.ceil((bytes.length * 8) / 5) !== secret.length) throw new Error('MURMUR_TOTP_SECRET has an invalid Base32 length.')
  let bits = 0
  let remaining = 0
  let offset = 0
  for (const char of secret) {
    bits = (bits << 5) | BASE32.indexOf(char)
    remaining += 5
    if (remaining >= 8) {
      remaining -= 8
      bytes[offset++] = bits >> remaining
      bits &= (1 << remaining) - 1
    }
  }
  if (bits !== 0) throw new Error('MURMUR_TOTP_SECRET has invalid trailing Base32 bits.')
  return bytes
}

/** RFC 6238 (SHA-1, six digits), allowing one time step of clock drift. */
export function totpCounter(secret: Buffer, code: unknown, now = Date.now()) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return null
  const current = Math.floor(now / STEP_MS)
  const given = Buffer.from(code)
  const message = Buffer.alloc(8)
  for (const counter of [current + 1, current, current - 1]) {
    if (counter < 0) continue
    message.writeBigUInt64BE(BigInt(counter))
    const hash = createHmac('sha1', secret).update(message).digest()
    const offset = hash[hash.length - 1] & 0xf
    const otp = ((hash.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0')
    if (timingSafeEqual(given, Buffer.from(otp))) return counter
  }
  return null
}
