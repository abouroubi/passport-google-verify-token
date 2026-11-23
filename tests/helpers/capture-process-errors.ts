type CapturedRun<T> = { result: T; processErrors: unknown[] };

/**
 * Runs `run` and collects every uncaught exception and unhandled promise rejection
 * raised until the next turn of the event loop after it settles.
 */
export async function captureProcessErrors<T>(run: () => Promise<T>): Promise<CapturedRun<T>> {
  // Vitest listens for these events itself and fails the run on any of them, so its
  // listeners are detached while capturing and restored afterwards.
  const vitestRejectionListeners = process.listeners('unhandledRejection');
  const vitestExceptionListeners = process.listeners('uncaughtException');
  const processErrors: unknown[] = [];
  const record = (error: unknown) => processErrors.push(error);
  process.removeAllListeners('unhandledRejection').on('unhandledRejection', record);
  process.removeAllListeners('uncaughtException').on('uncaughtException', record);
  try {
    const result = await run();
    await new Promise((resolve) => setImmediate(resolve));
    return { result, processErrors };
  } finally {
    process.off('unhandledRejection', record).off('uncaughtException', record);
    for (const listener of vitestRejectionListeners) {
      process.on('unhandledRejection', listener);
    }
    for (const listener of vitestExceptionListeners) {
      process.on('uncaughtException', listener);
    }
  }
}
