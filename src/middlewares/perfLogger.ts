// tptech-backend/src/middlewares/perfLogger.ts
import type { Request, Response, NextFunction } from "express";

export function perfLogger(opts?: { slowMs?: number }) {
  const slowMs = opts?.slowMs ?? 700;

  return (req: Request, res: Response, next: NextFunction) => {
    const start = process.hrtime.bigint();

    res.on("finish", () => {
      const end = process.hrtime.bigint();
      const ms = Number(end - start) / 1_000_000;

      // log siempre en dev; en prod solo si es lento
      const isProd = process.env.NODE_ENV === "production";
      const shouldLog = !isProd || ms >= slowMs;

      if (!shouldLog) return;

      const u = req.originalUrl || req.url;
      const line = [
        "[PERF]",
        req.method,
        u,
        res.statusCode,
        `${ms.toFixed(1)}ms`,
        req.tenantId ? `tenant=${req.tenantId}` : "",
        req.userId ? `user=${req.userId}` : "",
      ]
        .filter(Boolean)
        .join(" ");

      // eslint-disable-next-line no-console
      console.log(line);
    });

    next();
  };
}
