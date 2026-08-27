import type { RequestHandler } from "express";

interface RateLimitOptions {
  windowMs: number;
  max: number;
}

interface ClientWindow {
  count: number;
  resetAt: number;
}

export function createRateLimiter({ windowMs, max }: RateLimitOptions): RequestHandler {
  const clients = new Map<string, ClientWindow>();

  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip || req.socket.remoteAddress || "unknown";
    const existing = clients.get(key);
    const current = !existing || existing.resetAt <= now
      ? { count: 0, resetAt: now + windowMs }
      : existing;

    current.count += 1;
    clients.set(key, current);

    if (clients.size > 10_000) {
      clients.forEach((window, client) => {
        if (window.resetAt <= now) clients.delete(client);
      });
    }

    const remaining = Math.max(0, max - current.count);
    res.setHeader("RateLimit-Limit", max);
    res.setHeader("RateLimit-Remaining", remaining);
    res.setHeader("RateLimit-Reset", Math.ceil(current.resetAt / 1_000));

    if (current.count > max) {
      const retryAfter = Math.max(1, Math.ceil((current.resetAt - now) / 1_000));
      res.setHeader("Retry-After", retryAfter);
      res.status(429).json({ error: "Too many scan requests. Try again later." });
      return;
    }

    next();
  };
}
