import type { Request, Response } from "express";
import bcrypt from "bcryptjs";

import { prisma } from "../../lib/prisma.js";
import { verifyResetToken } from "../../lib/authTokens.js";

/**
 * POST /auth/reset-password
 * body: { token: string, newPassword: string }
 * Público (sin cookie). Actualiza password + tokenVersion++.
 */
export async function resetPassword(req: Request, res: Response) {
  const token = String((req.body as any)?.token || "").trim();
  const newPassword = String((req.body as any)?.newPassword || "");

  if (!token) return res.status(400).json({ message: "Falta token." });
  if (newPassword.trim().length < 6)
    return res.status(400).json({ message: "La contraseña debe tener al menos 6 caracteres." });

  let payload: { userId: string; jti: string };
  try {
    payload = verifyResetToken(token);
  } catch (e: any) {
    return res.status(400).json({ message: e?.message || "Token inválido o expirado." });
  }

  const user = await prisma.user.findFirst({
    where: { id: payload.userId, deletedAt: null },
    select: { id: true },
  });

  if (!user) return res.status(404).json({ message: "Usuario no encontrado." });

  const hash = await bcrypt.hash(newPassword, 10);

  await prisma.user.update({
    where: { id: user.id },
    data: {
      password: hash,
      status: "ACTIVE", // ✅ opcional: si era PENDING, lo activamos
      tokenVersion: { increment: 1 }, // ✅ invalida sesiones viejas
    },
    select: { id: true },
  });

  return res.json({ ok: true });
}
