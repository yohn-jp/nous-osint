export function release(options: Record<string, string>, dependencies?: Record<string, unknown>): Promise<{ sha: string; mode: string; version: string; zoneId: string }>;
