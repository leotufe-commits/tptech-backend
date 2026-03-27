// tptech-backend/src/modules/auth/auth.controller.ts
import type { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";

import { prisma } from "../../lib/prisma.js";
import { sendResetEmail } from "../../lib/mailer.js";
import { createAuthTokenRecord, consumeAuthToken } from "../../lib/authTokenStore.js";
import { auditLog } from "../../lib/auditLogger.js";
import { buildAuthResponse } from "../../lib/authResponse.js";
import { ensureGlobalPermissions, ensureSystemRoles, ensureSystemDefaults, ensureEmailBranding } from "../../lib/initTenantDefaults.js";
import { UserStatus } from "@prisma/client";
import type { Prisma } from "@prisma/client";

// ✅ Unificamos reset token/link en un solo lugar
import { signResetToken, buildResetLink, verifyResetToken } from "../../lib/authTokens.js";

/* =========================
   ENV / CONST
========================= */
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error("❌ JWT_SECRET no está configurado");
const JWT_SECRET_SAFE: string = JWT_SECRET;

const JWT_ISSUER = process.env.JWT_ISSUER || "tptech";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "tptech-web";
const AUTH_COOKIE = "tptech_session";

/* =========================
   HELPERS
========================= */
type AccessTokenPayload = { sub: string; tenantId: string; tokenVersion: number };

export function signToken(userId: string, tenantId: string, tokenVersion: number) {
  const payload: AccessTokenPayload = { sub: userId, tenantId, tokenVersion };
  return jwt.sign(payload, JWT_SECRET_SAFE, {
    expiresIn: "7d",
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  });
}

export function setAuthCookie(_req: Request, res: Response, token: string) {
  const isProd = process.env.NODE_ENV === "production";
  res.cookie(AUTH_COOKIE, token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
  });
}

export function clearAuthCookie(_req: Request, res: Response) {
  const isProd = process.env.NODE_ENV === "production";
  res.clearCookie(AUTH_COOKIE, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
    path: "/",
  });
}

export const s = (v: unknown) => String(v ?? "").trim();

export function isPrismaUniqueError(e: any) {
  return e && typeof e === "object" && (e.code === "P2002" || e.name === "PrismaClientKnownRequestError");
}
export function prismaUniqueTargets(e: any): string[] {
  const t = e?.meta?.target;
  if (Array.isArray(t)) return t.map(String);
  if (typeof t === "string") return [t];
  return [];
}


/* =========================
   PRISMA INCLUDES
========================= */
export const AUTH_USER_INCLUDE = {
  jewelry: true,
  favoriteWarehouse: true,
  roles: { include: { role: { include: { permissions: { include: { permission: true } } } } } },
  permissionOverrides: { include: { permission: true } },
} as const;

export async function fetchUserForAuthById(userId: string) {
  return prisma.user.findUnique({ where: { id: userId }, include: AUTH_USER_INCLUDE });
}

export async function fetchUserForAuthByEmailAndTenant(email: string, tenantId: string) {
  return prisma.user.findFirst({
    where: { email, jewelryId: tenantId, deletedAt: null },
    include: AUTH_USER_INCLUDE,
    orderBy: { createdAt: "asc" },
  });
}

export async function fetchUsersForLoginOptions(email: string) {
  const users = await prisma.user.findMany({
    where: { email, deletedAt: null },
    select: { jewelryId: true, jewelry: { select: { id: true, name: true } }, createdAt: true },
    orderBy: { createdAt: "asc" },
  });

  const map = new Map<string, { id: string; name: string }>();
  for (const u of users) {
    const j = (u as any).jewelry;
    if (j?.id && !map.has(j.id)) map.set(j.id, { id: j.id, name: j.name || "Joyería" });
  }
  return Array.from(map.values());
}

async function fetchMeUserWithOptionalAttachments(userId: string) {
  try {
    return await prisma.user.findUnique({
      where: { id: userId },
      include: {
        jewelry: { include: { attachments: true } } as any,
        favoriteWarehouse: true,
        roles: AUTH_USER_INCLUDE.roles,
        permissionOverrides: AUTH_USER_INCLUDE.permissionOverrides,
      },
    });
  } catch {
    return await prisma.user.findUnique({ where: { id: userId }, include: AUTH_USER_INCLUDE });
  }
}

/* =========================
   ME
========================= */
export async function me(req: Request, res: Response) {
  const userId = (req as any).userId as string | undefined;
  if (!userId) return res.status(401).json({ message: "Unauthorized" });

  const user = await fetchMeUserWithOptionalAttachments(userId);
  if (!user) return res.status(404).json({ message: "User not found." });

  if (user.status !== UserStatus.ACTIVE) {
    auditLog(req, {
      action: "auth.me",
      success: false,
      userId: user.id,
      tenantId: user.jewelryId,
      meta: { reason: "user_not_active" },
    });
    return res.status(403).json({ message: "Usuario no habilitado." });
  }

  return res.json(buildAuthResponse({ user, includeToken: false }));
}

/* =========================
   REGISTER
========================= */
/* =========================
   REGISTER
========================= */
export async function register(req: Request, res: Response) {
  const data = req.body as any;
  const email = s(data.email).toLowerCase();
  const hashed = await bcrypt.hash(String(data.password ?? ""), 10);

  try {
    // timeout: 30s — el registro crea ~150 registros de defaults en una sola TX
    const result = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {

      // 1️⃣ Crear Jewelry
      const jewelry = await tx.jewelry.create({
        data: {
          name: s(data.jewelryName),
          firstName: s(data.firstName),
          lastName: s(data.lastName),
          phoneCountry: s(data.phoneCountry),
          phoneNumber: s(data.phoneNumber),
          street: s(data.street),
          number: s(data.number),
          city: s(data.city),
          province: s(data.province),
          postalCode: s(data.postalCode),
          country: s(data.country),
        },
      });

      // 2️⃣ Crear almacén Principal automático
      const principalWarehouse = await tx.warehouse.create({
        data: {
          jewelryId: jewelry.id,
          name: "Principal",
          code: "PRINCIPAL",
          isActive: true,
        },
      });

      // 3️⃣ Crear permisos base, roles y defaults del sistema
      const permIdByKey = await ensureGlobalPermissions(tx);
      const { ownerRoleId } = await ensureSystemRoles(tx, jewelry.id, permIdByKey);
      await ensureSystemDefaults(tx, jewelry.id);
      await ensureEmailBranding(tx, jewelry, email);

      // 4️⃣ Crear usuario OWNER con almacén favorito
      const user = await tx.user.create({
        data: {
          email,
          password: hashed,
          firstName: s(data.firstName),
          lastName: s(data.lastName),
          name: `${s(data.firstName)} ${s(data.lastName)}`.trim() || null,
          phoneCountry: s(data.phoneCountry),
          phoneNumber: s(data.phoneNumber),
          street: s(data.street),
          number: s(data.number),
          city: s(data.city),
          province: s(data.province),
          postalCode: s(data.postalCode),
          country: s(data.country),
          status: UserStatus.ACTIVE,
          jewelryId: jewelry.id,
          tokenVersion: 0,
          favoriteWarehouseId: principalWarehouse.id,
        },
      });

      await tx.userRole.create({
        data: { userId: user.id, roleId: ownerRoleId },
      });

      const fullUser = await tx.user.findUniqueOrThrow({
        where: { id: user.id },
        include: AUTH_USER_INCLUDE,
      });

      return { user: fullUser, jewelry };
    }, { timeout: 30_000 });

    const token = signToken(
      result.user.id,
      result.user.jewelryId,
      result.user.tokenVersion
    );

    setAuthCookie(req, res, token);

    auditLog(req, {
      action: "auth.register",
      success: true,
      userId: result.user.id,
      tenantId: result.user.jewelryId,
      meta: { email },
    });

    return res.status(201).json(
      buildAuthResponse({
        user: { ...result.user, jewelry: result.jewelry },
        token,
        includeToken: true,
      })
    );
  } catch (e: any) {
    if (isPrismaUniqueError(e)) {
      const targets = prismaUniqueTargets(e);
      if (targets.includes("email") || targets.join(",").includes("email")) {
        auditLog(req, {
          action: "auth.register",
          success: false,
          meta: { email, reason: "unique_email_conflict" },
        });
        return res.status(409).json({ message: "El email ya está registrado." });
      }
    }

    // Log detallado para diagnóstico — incluye el mensaje real del error
    console.error("[register] Error inesperado:", {
      message: e?.message,
      code:    e?.code,
      meta:    e?.meta,
      stack:   e?.stack?.split("\n").slice(0, 6).join(" | "),
    });

    auditLog(req, {
      action: "auth.register",
      success: false,
      meta: { email, reason: "unknown_error", errorMessage: e?.message },
    });

    return res.status(500).json({ message: "No se pudo registrar." });
  }
}

/* =========================
   LOGIN
========================= */
export async function login(req: Request, res: Response) {
  const data = req.body as any;
  const email = s(data.email).toLowerCase();
  const password = String(data.password ?? "");
  const tenantId = s(data.tenantId || "");

  if (!email || !password) {
    auditLog(req, { action: "auth.login", success: false, meta: { email, reason: "missing_fields" } });
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  const tenants = await fetchUsersForLoginOptions(email);
  if (tenants.length === 0) {
    auditLog(req, { action: "auth.login", success: false, meta: { email, reason: "user_not_found" } });
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  if (tenants.length > 1 && !tenantId) {
    auditLog(req, {
      action: "auth.login",
      success: false,
      meta: { email, reason: "tenant_required", tenantsCount: tenants.length },
    });
    return res.status(409).json({ message: "Seleccioná la joyería para iniciar sesión.", code: "TENANT_REQUIRED", tenants });
  }

  const finalTenantId = tenantId || tenants[0]?.id;
  const user = await fetchUserForAuthByEmailAndTenant(email, finalTenantId);

  if (!user || (user as any).deletedAt) {
    auditLog(req, {
      action: "auth.login",
      success: false,
      meta: { email, reason: "user_not_found_in_tenant", tenantId: finalTenantId },
    });
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  if (user.status !== UserStatus.ACTIVE) {
    auditLog(req, {
      action: "auth.login",
      success: false,
      userId: user.id,
      tenantId: user.jewelryId,
      meta: { email, reason: user.status === UserStatus.BLOCKED ? "user_blocked" : "user_pending" },
    });
    const loginBlockedMsg =
      user.status === UserStatus.BLOCKED
        ? "Tu cuenta está bloqueada. Contactá al administrador."
        : "Tu cuenta está pendiente de activación. Revisá tu email para activarla.";
    return res.status(403).json({ message: loginBlockedMsg });
  }

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    auditLog(req, {
      action: "auth.login",
      success: false,
      userId: user.id,
      tenantId: user.jewelryId,
      meta: { email, reason: "invalid_password" },
    });
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  const token = signToken(user.id, user.jewelryId, user.tokenVersion);
  setAuthCookie(req, res, token);

  auditLog(req, {
    action: "auth.login",
    success: true,
    userId: user.id,
    tenantId: user.jewelryId,
    meta: { selectedTenantId: user.jewelryId },
  });

  return res.json(buildAuthResponse({ user, token, includeToken: true }));
}

/* =========================
   LOGOUT
========================= */
export async function logout(req: Request, res: Response) {
  clearAuthCookie(req, res);
  auditLog(req, { action: "auth.logout", success: true, userId: (req as any).userId, tenantId: (req as any).tenantId });
  return res.json({ ok: true });
}

/* =========================
   FORGOT PASSWORD (single-use)
========================= */
export async function forgotPassword(req: Request, res: Response) {
  const data = req.body as any;
  const email = s(data.email).toLowerCase();

  const user = await prisma.user.findFirst({
    where: { email, deletedAt: null },
    select: { id: true, jewelryId: true, email: true },
    orderBy: { createdAt: "asc" },
  });

  // Por seguridad: siempre ok
  if (!user) {
    auditLog(req, { action: "auth.forgot_password", success: true, meta: { email, userFound: false } });
    return res.json({ ok: true });
  }

  const jti = crypto.randomUUID();
  const resetToken = signResetToken(user.id, jti, "30m");
  const resetLink = buildResetLink(resetToken);

  // ✅ single-use: guardamos registro en DB con expiración (30m)
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
  await createAuthTokenRecord({
    type: "reset",
    userId: user.id,
    jti,
    expiresAt,
    emailSnapshot: user.email,
    req,
  });

  await sendResetEmail(email, resetLink);

  auditLog(req, {
    action: "auth.forgot_password",
    success: true,
    userId: user.id,
    tenantId: user.jewelryId,
    meta: { email, userFound: true, jti },
  });

  return res.json({ ok: true });
}

/* =========================
   RESET PASSWORD (single-use)
========================= */
export async function resetPassword(req: Request, res: Response) {
  const data = req.body as any;

  try {
    const token = String(data.token || "");
    const newPassword = String(data.newPassword ?? "");

    if (!token) return res.status(400).json({ message: "Token requerido." });
    if (newPassword.trim().length < 6) return res.status(400).json({ message: "La contraseña debe tener al menos 6 caracteres." });

    // ✅ 1) Verificamos JWT (firma/issuer/audience/type)
    const { userId, jti } = verifyResetToken(token);

    // ✅ 2) Single-use (si ya se usó o no existe, falla)
    const result = await consumeAuthToken({ userId, jti });

    if (!result.ok) {
      const msgMap: Record<string, string> = {
        not_found: "Token inválido.",
        wrong_type: "Token inválido.",
        user_mismatch: "Token inválido.",
        already_used: "Este link ya fue usado.",
        expired: "Este link expiró. Pedí uno nuevo.",
        race: "Token inválido.",
      };
      const safeMsg = msgMap[result.reason] ?? "Token inválido.";
      auditLog(req, { action: "auth.reset_password", success: false, meta: { reason: result.reason, jti } });
      return res.status(401).json({ message: safeMsg });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, jewelryId: true, status: true, deletedAt: true },
    });

    if (!user || user.deletedAt) {
      auditLog(req, { action: "auth.reset_password", success: false, meta: { reason: "user_not_found" } });
      return res.status(401).json({ message: "Token inválido." });
    }

    const newHash = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { id: userId },
      data: {
        password: newHash,
        tokenVersion: { increment: 1 },
        status: user.status === UserStatus.PENDING ? UserStatus.ACTIVE : user.status,
      },
    });

    clearAuthCookie(req, res);

    auditLog(req, {
      action: "auth.reset_password",
      success: true,
      userId: user.id,
      tenantId: user.jewelryId,
      meta: { jti, activated: user.status === UserStatus.PENDING },
    });

    return res.json({ ok: true });
  } catch {
    // verifyResetToken lanzó error (JWT inválido o expirado a nivel firma)
    auditLog(req, { action: "auth.reset_password", success: false, meta: { reason: "jwt_invalid" } });
    return res.status(401).json({ message: "Token inválido." });
  }
}

/* =========================
   CHANGE PASSWORD (autenticado)
========================= */
export async function changePassword(req: Request, res: Response) {
  const userId = (req as any).userId as string;
  const { currentPassword, newPassword } = req.body as {
    currentPassword: string;
    newPassword: string;
  };

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, password: true, jewelryId: true, tokenVersion: true },
  });

  if (!user) return res.status(404).json({ message: "Usuario no encontrado." });

  const ok = await bcrypt.compare(currentPassword, user.password);
  if (!ok) {
    auditLog(req, {
      action: "auth.change_password",
      success: false,
      userId,
      tenantId: user.jewelryId,
      meta: { reason: "wrong_current_password" },
    });
    return res.status(400).json({ message: "La contraseña actual es incorrecta." });
  }

  const newHash = await bcrypt.hash(newPassword, 10);

  const updated = await prisma.user.update({
    where: { id: userId },
    data: {
      password: newHash,
      tokenVersion: { increment: 1 },
    },
    select: { id: true, jewelryId: true, tokenVersion: true },
  });

  // ✅ Re-emitir cookie con tokenVersion actualizado para mantener la sesión activa
  const newToken = signToken(updated.id, updated.jewelryId, updated.tokenVersion);
  setAuthCookie(req, res, newToken);

  auditLog(req, {
    action: "auth.change_password",
    success: true,
    userId,
    tenantId: user.jewelryId,
  });

  return res.json({ ok: true });
}

/* =========================
   LOGIN OPTIONS
========================= */
export async function loginOptions(req: Request, res: Response) {
  const rawEmail = String((req.body as any)?.email ?? "").toLowerCase().trim();
  if (!rawEmail) return res.status(400).json({ message: "Email requerido." });

  const tenants = await fetchUsersForLoginOptions(rawEmail);
  return res.json({ email: rawEmail, tenants });
}

/* =========================
   VERIFY TOKEN (sin consumir)
========================= */
export async function verifyToken(req: Request, res: Response) {
  const token = String((req.query as any)?.token ?? "").trim();
  if (!token) return res.status(400).json({ ok: false, reason: "missing", message: "Token requerido." });

  try {
    const { userId, jti } = verifyResetToken(token);

    const row = await prisma.authToken.findUnique({
      where: { jti },
      select: { usedAt: true, expiresAt: true, userId: true },
    });

    if (!row || String(row.userId) !== String(userId)) {
      return res.status(401).json({ ok: false, reason: "invalid", message: "Token inválido." });
    }
    if (row.usedAt) {
      return res.status(401).json({ ok: false, reason: "already_used", message: "Este link ya fue usado." });
    }
    if (row.expiresAt.getTime() < Date.now()) {
      return res.status(401).json({ ok: false, reason: "expired", message: "Este link expiró." });
    }

    return res.json({ ok: true });
  } catch {
    return res.status(401).json({ ok: false, reason: "invalid", message: "Token inválido." });
  }
}