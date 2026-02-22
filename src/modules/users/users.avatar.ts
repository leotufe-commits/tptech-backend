// tptech-backend/src/modules/users/users.avatar.ts
import type { Request, Response } from "express";
import { prisma } from "../../lib/prisma.js";
import { auditLog } from "../../lib/auditLogger.js";
import { toPublicUploadUrl, safeDeleteLocalUploadByUrl } from "../../lib/uploads/localUploads.js";

// mini helper (igual a company.controller)
function requireTenantId(req: Request, res: Response): string | null {
  const tenantId = (req as any).tenantId as string | undefined;
  if (!tenantId) {
    res.status(400).json({ message: "Tenant no definido en el request." });
    return null;
  }
  return String(tenantId);
}

function requireActorId(req: Request, res: Response): string | null {
  const actorId = (req as any).userId as string | undefined;
  if (!actorId) {
    res.status(401).json({ message: "No autenticado." });
    return null;
  }
  return String(actorId);
}

function requireParamId(req: Request, res: Response, key: string) {
  const v = String((req.params as any)?.[key] || "").trim();
  if (!v) {
    res.status(400).json({ message: `${key} inválido.` });
    return null;
  }
  return v;
}

/* =========================================================
   ✅ /ME
========================================================= */

/**
 * ✅ PUT /users/me/avatar
 * multipart field: avatar (imagen)
 * middleware: uploadAvatar.single("avatar")
 */
export async function uploadMyAvatar(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const actorId = requireActorId(req, res);
  if (!actorId) return;

  const file = (req as any).file as Express.Multer.File | undefined;
  if (!file) return res.status(400).json({ message: "Falta archivo avatar (field: avatar)." });

  if (!file.mimetype?.startsWith("image/")) {
    return res.status(400).json({ message: "El avatar debe ser una imagen." });
  }

  const prev = await prisma.user.findFirst({
    where: { id: actorId, jewelryId: tenantId, deletedAt: null },
    select: { id: true, avatarUrl: true },
  });
  if (!prev) return res.status(404).json({ message: "Usuario no encontrado." });

  // ✅ NUEVO: users/avatars
  const avatarUrl = toPublicUploadUrl(req, "users/avatars", file.filename);

  const updated = await prisma.user.update({
    where: { id: actorId },
    data: { avatarUrl },
    select: { id: true, avatarUrl: true },
  });

  // ✅ borrar anterior (nuevo path)
  await safeDeleteLocalUploadByUrl(prev.avatarUrl ?? null, "users/avatars");
  // ✅ compat: si antes guardabas /uploads/avatars/...
  await safeDeleteLocalUploadByUrl(prev.avatarUrl ?? null, "avatars");

  auditLog(req, {
    action: "users.avatar.upload",
    success: true,
    userId: actorId,
    tenantId,
    meta: { avatarUrl },
  });

  return res.json({ ok: true, avatarUrl: updated.avatarUrl });
}

/**
 * ✅ DELETE /users/me/avatar
 */
export async function deleteMyAvatar(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const actorId = requireActorId(req, res);
  if (!actorId) return;

  const prev = await prisma.user.findFirst({
    where: { id: actorId, jewelryId: tenantId, deletedAt: null },
    select: { id: true, avatarUrl: true },
  });
  if (!prev) return res.status(404).json({ message: "Usuario no encontrado." });

  const updated = await prisma.user.update({
    where: { id: actorId },
    data: { avatarUrl: null },
    select: { id: true, avatarUrl: true },
  });

  await safeDeleteLocalUploadByUrl(prev.avatarUrl ?? null, "users/avatars");
  await safeDeleteLocalUploadByUrl(prev.avatarUrl ?? null, "avatars");

  auditLog(req, {
    action: "users.avatar.delete",
    success: true,
    userId: actorId,
    tenantId,
    meta: { prevAvatarUrl: prev.avatarUrl ?? "" },
  });

  return res.json({ ok: true, avatarUrl: updated.avatarUrl });
}

/* =========================================================
   ✅ ADMIN (por :id)
========================================================= */

/**
 * ✅ PUT /users/:id/avatar  (ADMIN)
 * multipart field: avatar (imagen)
 * middleware: uploadAvatar.single("avatar")
 */
export async function uploadUserAvatar(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const actorId = requireActorId(req, res);
  if (!actorId) return;

  const targetUserId = requireParamId(req, res, "id");
  if (!targetUserId) return;

  const file = (req as any).file as Express.Multer.File | undefined;
  if (!file) return res.status(400).json({ message: "Falta archivo avatar (field: avatar)." });

  if (!file.mimetype?.startsWith("image/")) {
    return res.status(400).json({ message: "El avatar debe ser una imagen." });
  }

  const prev = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true, avatarUrl: true },
  });
  if (!prev) return res.status(404).json({ message: "Usuario no encontrado." });

  const avatarUrl = toPublicUploadUrl(req, "users/avatars", file.filename);

  const updated = await prisma.user.update({
    where: { id: targetUserId },
    data: { avatarUrl },
    select: { id: true, avatarUrl: true },
  });

  await safeDeleteLocalUploadByUrl(prev.avatarUrl ?? null, "users/avatars");
  await safeDeleteLocalUploadByUrl(prev.avatarUrl ?? null, "avatars");

  auditLog(req, {
    action: "users.avatar.admin.upload",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId, avatarUrl },
  });

  return res.json({ ok: true, userId: updated.id, avatarUrl: updated.avatarUrl });
}

/**
 * ✅ DELETE /users/:id/avatar (ADMIN)
 */
export async function deleteUserAvatar(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const actorId = requireActorId(req, res);
  if (!actorId) return;

  const targetUserId = requireParamId(req, res, "id");
  if (!targetUserId) return;

  const prev = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true, avatarUrl: true },
  });
  if (!prev) return res.status(404).json({ message: "Usuario no encontrado." });

  const updated = await prisma.user.update({
    where: { id: targetUserId },
    data: { avatarUrl: null },
    select: { id: true, avatarUrl: true },
  });

  await safeDeleteLocalUploadByUrl(prev.avatarUrl ?? null, "users/avatars");
  await safeDeleteLocalUploadByUrl(prev.avatarUrl ?? null, "avatars");

  auditLog(req, {
    action: "users.avatar.admin.delete",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId, prevAvatarUrl: prev.avatarUrl ?? "" },
  });

  return res.json({ ok: true, userId: updated.id, avatarUrl: updated.avatarUrl });
}