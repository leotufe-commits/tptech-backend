// src/middlewares/errorHandler.ts
import type { ErrorRequestHandler } from "express";

export const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  console.error("❌ ERROR:", err);

  const status =
    typeof (err as any)?.status === "number"
      ? (err as any).status
      : typeof (err as any)?.statusCode === "number"
        ? (err as any).statusCode
        : 500;

  const message =
    typeof (err as any)?.message === "string" ? (err as any).message : "Internal Server Error";

  res.status(status).json({ ok: false, message });
};
