/** Drop empty query-string values so optional filters stay omitted. */
export function cleanParams(
  params: Record<string, unknown>,
): Record<string, unknown> {
  const output: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    output[key] = value
  }
  return output
}
