// tptech-backend/src/lib/prisma.ts
import { AsyncLocalStorage } from "node:async_hooks";
import type { Request, Response, NextFunction } from "express";

// ✅ Prisma 7 — requiere adapter explícito para conexión directa
import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
export const prisma = new PrismaClient({ adapter });

/* =========================
   Prisma ALS (request context)
========================= */
type Ctx = { reqId: string };

const als = new AsyncLocalStorage<Ctx>();

function makeReqId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

export function getRequestContext() {
  return als.getStore() || null;
}

export function requestContextMiddleware(req: Request, _res: Response, next: NextFunction) {
  const reqId =
    (req.headers["x-request-id"] as string) ||
    (req.headers["x-correlation-id"] as string) ||
    makeReqId();

  als.run({ reqId }, next);
}
