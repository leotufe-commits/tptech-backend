// tptech-backend/src/lib/authTokenStore.ts
import type { Request } from "express";
import { prisma } from "./prisma.js";

/* =========================
   Helpers
========================= */

function getReqIp(req: Request) {
  const xf = String(req.headers["x-forwarded-for"] || "").split(",")[0]?.trim();
  return xf || (req.socket?.remoteAddress ? String(req.socket.remoteAddress) : undefined);
}

async function cleanupResetAuthTokens() {
  try {
    await prisma.authToken.deleteMany({
      where: {
        type: "reset",
        OR: [{ expiresAt: { lt: new Date() } }, { usedAt: { not: null } }],
      },
    });
  } catch {
    // ignore
  }
}

/* =========================
   Create
========================= */

export async function createAuthTokenRecord(args: {
  type: "reset";
  userId: string;
  jti: string;
  expiresAt: Date;
  emailSnapshot?: string;
  req: Request;
}) {
  const { type, userId, jti, expiresAt, emailSnapshot, req } = args;

  // higiene best-effort (no rompe si falla)
  await cleanupResetAuthTokens();

  return prisma.authToken.create({
    data: {
      type,
      jti,
      userId,
      expiresAt,
      emailSnapshot: String(emailSnapshot || ""),
      ip: getReqIp(req),
      userAgent: String(req.headers["user-agent"] || ""),
    },
    select: { id: true, jti: true },
  });
}

/* =========================
   Consume (single-use real)
   - valida: existe, es del user, no expiró, no usado
   - marca usedAt atómicamente
========================= */

export async function consumeResetAuthToken(args: { userId: string; jti: string }) {
  const { userId, jti } = args;
  const now = new Date();

  // 1) buscamos el token
  const row = await prisma.authToken.findUnique({
    where: { jti },
    select: { id: true, userId: true, expiresAt: true, usedAt: true, type: true },
  });

  if (!row) return { ok: false as const, reason: "not_found" as const };
  if (row.type !== "reset") return { ok: false as const, reason: "wrong_type" as const };
  if (row.userId !== userId) return { ok: false as const, reason: "user_mismatch" as const };
  if (row.usedAt) return { ok: false as const, reason: "already_used" as const };
  if (row.expiresAt.getTime() < now.getTime()) return { ok: false as const, reason: "expired" as const };

  // 2) marcamos usedAt de forma segura (id + usedAt null)
  const updated = await prisma.authToken.updateMany({
    where: { id: row.id, usedAt: null },
    data: { usedAt: now },
  });

  if (updated.count !== 1) return { ok: false as const, reason: "race" as const };

  return { ok: true as const };
}
