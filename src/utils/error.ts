export const createError = (
  error: string,
  status = 'error',
  reason?: string,
) => ({
  status,
  error,
  reason,
})
