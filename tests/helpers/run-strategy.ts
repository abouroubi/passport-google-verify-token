import type { GoogleTokenStrategy } from '../../src/strategy';

export type StrategyOutcome =
  | { kind: 'success'; user: unknown; info: unknown }
  | { kind: 'fail'; challenge: unknown; status: number | undefined }
  | { kind: 'error'; error: unknown };

type AuthenticateRequest = Parameters<GoogleTokenStrategy['authenticate']>[0];

interface CollectOptions {
  /** How many actions to wait for. */
  expected: number;
  /** Runs inside each action the strategy calls, as Passport's own action handlers do. */
  onOutcome?: (outcome: StrategyOutcome) => void;
}

/**
 * Runs `strategy.authenticate(req)` the way Passport does and resolves with the
 * action the strategy calls. Rejects if it calls more than one, since Passport
 * would then respond to the same request twice.
 */
export async function runStrategy(strategy: GoogleTokenStrategy, req: AuthenticateRequest): Promise<StrategyOutcome> {
  const outcomes = await collectOutcomes(strategy, req, { expected: 1 });
  if (outcomes.length !== 1) {
    throw new Error(`expected exactly one outcome, got: ${outcomes.map((o) => o.kind).join(', ')}`);
  }
  return outcomes[0];
}

/**
 * Runs `strategy.authenticate(req)` on a per-request instance that has the
 * success/fail/error actions attached, as Passport does. Once `expected` actions
 * have been called it waits one more turn of the event loop, so that an extra call
 * made in the same chain is included, and resolves with every action in order.
 */
export function collectOutcomes(
  strategy: GoogleTokenStrategy,
  req: AuthenticateRequest,
  { expected, onOutcome }: CollectOptions,
): Promise<StrategyOutcome[]> {
  return new Promise((resolve, reject) => {
    const outcomes: StrategyOutcome[] = [];
    const record = (outcome: StrategyOutcome) => {
      outcomes.push(outcome);
      if (outcomes.length === expected) {
        setImmediate(() => resolve([...outcomes]));
      }
      onOutcome?.(outcome);
    };

    // Object.create() is typed as returning `any`; the prototype is what gives the instance its shape.
    const instance = Object.create(strategy) as GoogleTokenStrategy;
    instance.success = (user: unknown, info?: unknown) => record({ kind: 'success', user, info });
    instance.fail = (challenge?: unknown, status?: number) =>
      typeof challenge === 'number'
        ? record({ kind: 'fail', challenge: undefined, status: challenge })
        : record({ kind: 'fail', challenge, status });
    instance.error = (error: unknown) => record({ kind: 'error', error });
    instance.redirect = (url: string) => reject(new Error(`unexpected redirect to ${url}`));
    instance.pass = () => reject(new Error('unexpected pass'));

    instance.authenticate(req);
  });
}
