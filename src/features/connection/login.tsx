import { useState, type FormEvent } from 'react'
import { motion, useAnimate } from 'motion/react'
import { Button } from '@/ui/button'
import { ByUmbrel } from '@/ui/brand'
import { usePrefersReducedMotion } from '@/lib/use-media'
import { BrandHeader } from './brand-header'
import { Field, Note, PasswordField } from './fields'

const HUE = 278

type Props = {
  step: 'password' | 'code'
  onSubmit: (value: string) => Promise<'signed-in' | 'next' | 'failed'>
  error?: string | null
  onEdit?: () => void
  /** Called once the success beat has played. */
  onSignedIn?: () => void
}

export function LoginScreen({ step, onSubmit, error, onEdit, onSignedIn }: Props) {
  const [value, setValue] = useState('')
  const code = step === 'code'
  const ready = code ? /^\d{6}$/.test(value) : !!value
  const [phase, setPhase] = useState<'idle' | 'busy' | 'done'>('idle')
  const [scope, animate] = useAnimate()
  const reduced = usePrefersReducedMotion()

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!ready || phase !== 'idle') return
    setPhase('busy')
    const result = await onSubmit(value)
    if (result === 'signed-in') {
      setPhase('done')
      setTimeout(() => onSignedIn?.(), 650)
      return
    }
    if (result === 'next') return
    setPhase('idle')
    if (!reduced) void animate(scope.current, { x: [0, -9, 8, -5, 3, 0] }, { duration: 0.42, ease: 'easeOut' })
    ;(scope.current as HTMLElement | null)?.querySelector('input')?.select()
  }

  const edit = (next: string) => {
    setValue(next)
    if (error) onEdit?.()
  }

  return (
    <main className="flex min-h-dvh flex-col bg-bg safe-top md:justify-center md:py-12" style={{ '--hue': HUE } as React.CSSProperties}>
      {/* Laid out like Connect to Hermes: the same column, header and signature, so the two read as one place. */}
      <form onSubmit={submit} className="mx-auto w-full max-w-[30rem] flex-1 px-5 pt-14 md:flex-none md:pt-0">
        <motion.div
          initial={{ opacity: 0, y: 12, filter: 'blur(6px)' }}
          animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
        >
          {/* Signed in: the two of them hop for joy before the app takes over. */}
          <BrandHeader
            hop={phase === 'done'}
            title={code ? 'Two-factor authentication' : 'Sign in'}
            body={code ? 'Enter the six-digit code from your authenticator app.' : 'Enter your password to continue.'}
          />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1], delay: 0.08 }}
          className="mt-9"
        >
          <div ref={scope}>
            {code ? (
              <Field
                value={value}
                onChange={(e) => edit(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="Authenticator code"
                aria-label="Authenticator code"
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
                invalid={!!error}
              />
            ) : (
              <PasswordField
                value={value}
                onChange={(e) => edit(e.target.value)}
                placeholder="Password"
                aria-label="Password"
                autoComplete="current-password"
                autoFocus
                invalid={!!error}
              />
            )}
          </div>
          <Note tone="danger">{error}</Note>
          <Button type="submit" size="lg" variant="accent" className="mt-4" loading={phase === 'busy'} disabled={!ready || phase === 'done'}>
            Continue
          </Button>
        </motion.div>
      </form>
      <footer className="flex justify-center pt-8 pb-[max(24px,env(safe-area-inset-bottom))] md:pb-0">
        <ByUmbrel />
      </footer>
    </main>
  )
}
