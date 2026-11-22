type CapturedRun<T> = { result: T; processErrors: unknown[] };
type VitestListeners = NodeJS.UnhandledRejectionListener[] | NodeJS.UncaughtExceptionListener[];

/** Runs `run` and collects every unhandled promise rejection until the next turn of the event loop. */
export function captureUnhandledRejections<T>(run: () => Promise<T>): Promise<CapturedRun<T>> {
  return captureProcessErrors('unhandledRejection', process.listeners('unhandledRejection'), run);
}

/** Runs `run` and collects every uncaught exception until the next turn of the event loop. */
export function captureUncaughtExceptions<T>(run: () => Promise<T>): Promise<CapturedRun<T>> {
  return captureProcessErrors('uncaughtException', process.listeners('uncaughtException'), run);
}

// Vitest listens for these events itself and fails the run on any of them, so its
// listeners are detached while capturing and restored afterwards.
async function captureProcessErrors<T>(
  event: 'unhandledRejection' | 'uncaughtException',
  vitestListeners: VitestListeners,
  run: () => Promise<T>,
): Promise<CapturedRun<T>> {
  const processErrors: unknown[] = [];
  const record = (error: unknown) => processErrors.push(error);
  process.removeAllListeners(event);
  process.on(event, record);
  try {
    const result = await run();
    await new Promise((resolve) => setImmediate(resolve));
    return { result, processErrors };
  } finally {
    process.off(event, record);
    for (const listener of vitestListeners) {
      process.on(event, listener);
    }
  }
}
