// tptech-backend/src/controllers/auth.base.controller.ts
import type { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";

import { prisma } from "../lib/prisma.js";
import { sendResetEmail } from "../lib/mailer.js";
import { auditLog } from "../lib/auditLogger.js";
import { buildAuthResponse } from "../lib/authResponse.js";
import { UserStatus, PermModule, PermAction } from "@prisma/client";
import type { Prisma, Permission as PermissionRow } from "@prisma/client";

/* =========================
   ENV / CONST
========================= */
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error("❌ JWT_SECRET no está configurado");
const JWT_SECRET_SAFE: string = JWT_SECRET;

const APP_URL = process.env.APP_URL || "http://localhost:5174";
const JWT_ISSUER = process.env.JWT_ISSUER || "tptech";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "tptech-web";
const AUTH_COOKIE = "tptech_session";

/* =========================
   HELPERS
========================= */
type AccessTokenPayload = { sub: string; tenantId: string; tokenVersion: number };

export function signToken(userId: string, tenantId: string, tokenVersion: number) {
  const payload: AccessTokenPayload = { sub: userId, tenantId, tokenVersion };
  return jwt.sign(payload, JWT_SECRET_SAFE, { expiresIn: "7d", issuer: JWT_ISSUER, audience: JWT_AUDIENCE });
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
export async function register(req: Request, res: Response) {
  const data = req.body as any;
  const email = s(data.email).toLowerCase();
  const hashed = await bcrypt.hash(String(data.password ?? ""), 10);

  const ALL_MODULES = Object.values(PermModule);
  const ALL_ACTIONS = Object.values(PermAction);

  try {
    const result = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
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

      const permissionsData: { module: PermModule; action: PermAction }[] = [];
      for (const module of ALL_MODULES) for (const action of ALL_ACTIONS) permissionsData.push({ module, action });

      await tx.permission.createMany({ data: permissionsData, skipDuplicates: true });

      const allPermissions: PermissionRow[] = await tx.permission.findMany();
      const permIdByKey = new Map<string, string>();
      for (const p of allPermissions) permIdByKey.set(`${p.module}:${p.action}`, p.id);

      const pick = (modules: PermModule[], actions: PermAction[]) => {
        const ids: string[] = [];
        for (const m of modules) for (const a of actions) {
          const id = permIdByKey.get(`${m}:${a}`);
          if (id) ids.push(id);
        }
        return ids;
      };

      const rolesToCreate = [
        { name: "OWNER", isSystem: true, permIds: allPermissions.map((p) => p.id) },
        { name: "ADMIN", isSystem: true, permIds: pick(ALL_MODULES as PermModule[], ALL_ACTIONS as PermAction[]) },
        { name: "STAFF", isSystem: true, permIds: pick(ALL_MODULES as PermModule[], [PermAction.VIEW, PermAction.CREATE, PermAction.EDIT]) },
        { name: "READONLY", isSystem: true, permIds: pick(ALL_MODULES as PermModule[], [PermAction.VIEW]) },
      ] as const;

      let ownerRoleId = "";
      for (const r of rolesToCreate) {
        const role = await tx.role.create({ data: { name: r.name, jewelryId: jewelry.id, isSystem: r.isSystem } });
        if (r.name === "OWNER") ownerRoleId = role.id;

        await tx.rolePermission.createMany({
          data: r.permIds.map((permissionId) => ({ roleId: role.id, permissionId })),
          skipDuplicates: true,
        });
      }

      const user = await tx.user.create({
        data: {
          email,
          password: hashed,
          name: `${s(data.firstName)} ${s(data.lastName)}`.trim(),
          status: UserStatus.ACTIVE,
          jewelryId: jewelry.id,
          tokenVersion: 0,
        },
      });

      await tx.userRole.create({ data: { userId: user.id, roleId: ownerRoleId } });

      const fullUser = await tx.user.findUniqueOrThrow({ where: { id: user.id }, include: AUTH_USER_INCLUDE });
      return { user: fullUser, jewelry };
    });

    const token = signToken(result.user.id, result.user.jewelryId, result.user.tokenVersion);
    setAuthCookie(req, res, token);

    auditLog(req, { action: "auth.register", success: true, userId: result.user.id, tenantId: result.user.jewelryId, meta: { email } });

    return res.status(201).json(
      buildAuthResponse({ user: { ...result.user, jewelry: result.jewelry }, token, includeToken: true })
    );
  } catch (e: any) {
    if (isPrismaUniqueError(e)) {
      const targets = prismaUniqueTargets(e);
      if (targets.includes("email") || targets.join(",").includes("email")) {
        auditLog(req, { action: "auth.register", success: false, meta: { email, reason: "unique_email_conflict" } });
        return res.status(409).json({ message: "El email ya está registrado." });
      }
    }
    auditLog(req, { action: "auth.register", success: false, meta: { email, reason: "unknown_error" } });
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
    auditLog(req, { action: "auth.login", success: false, meta: { email, reason: "tenant_required", tenantsCount: tenants.length } });
    return res.status(409).json({ message: "Seleccioná la joyería para iniciar sesión.", code: "TENANT_REQUIRED", tenants });
  }

  const finalTenantId = tenantId || tenants[0]?.id;
  const user = await fetchUserForAuthByEmailAndTenant(email, finalTenantId);

  if (!user || (user as any).deletedAt) {
    auditLog(req, { action: "auth.login", success: false, meta: { email, reason: "user_not_found_in_tenant", tenantId: finalTenantId } });
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  if (user.status !== UserStatus.ACTIVE) {
    auditLog(req, { action: "auth.login", success: false, userId: user.id, tenantId: user.jewelryId, meta: { email, reason: "user_blocked" } });
    return res.status(403).json({ message: "Usuario no habilitado." });
  }

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    auditLog(req, { action: "auth.login", success: false, userId: user.id, tenantId: user.jewelryId, meta: { email, reason: "invalid_password" } });
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  const token = signToken(user.id, user.jewelryId, user.tokenVersion);
  setAuthCookie(req, res, token);

  auditLog(req, { action: "auth.login", success: true, userId: user.id, tenantId: user.jewelryId, meta: { selectedTenantId: user.jewelryId } });

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
   FORGOT PASSWORD
========================= */
export async function forgotPassword(req: Request, res: Response) {
  const data = req.body as any;
  const email = s(data.email).toLowerCase();

  const user = await prisma.user.findFirst({
    where: { email, deletedAt: null },
    select: { id: true, jewelryId: true },
    orderBy: { createdAt: "asc" },
  });

  if (!user) {
    auditLog(req, { action: "auth.forgot_password", success: true, meta: { email, userFound: false } });
    return res.json({ ok: true });
  }

  const jti = crypto.randomUUID();
  const resetToken = jwt.sign({ sub: user.id, type: "reset", jti }, JWT_SECRET_SAFE, {
    expiresIn: "30m",
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  });

  const resetLink = `${APP_URL}/reset-password?token=${encodeURIComponent(resetToken)}`;
  await sendResetEmail(email, resetLink);

  auditLog(req, { action: "auth.forgot_password", success: true, userId: user.id, tenantId: user.jewelryId, meta: { email, userFound: true, jti } });
  return res.json({ ok: true });
}

/* =========================
   RESET PASSWORD
========================= */
export async function resetPassword(req: Request, res: Response) {
  const data = req.body as any;

  try {
    const payload = jwt.verify(String(data.token), JWT_SECRET_SAFE, { issuer: JWT_ISSUER, audience: JWT_AUDIENCE }) as any;

    if (!payload?.sub || payload?.type !== "reset" || !payload?.jti) {
      auditLog(req, { action: "auth.reset_password", success: false, meta: { reason: "invalid_token_payload" } });
      return res.status(401).json({ message: "Token inválido." });
    }

    const userId = String(payload.sub);
    const user = await prisma.user.findUnique({ where: { id: userId }, select: { id: true, jewelryId: true } });

    if (!user) {
      auditLog(req, { action: "auth.reset_password", success: false, meta: { reason: "user_not_found" } });
      return res.status(401).json({ message: "Token inválido." });
    }

    const newHash = await bcrypt.hash(String(data.newPassword ?? ""), 10);
    await prisma.user.update({ where: { id: userId }, data: { password: newHash, tokenVersion: { increment: 1 } } });

    clearAuthCookie(req, res);

    auditLog(req, { action: "auth.reset_password", success: true, userId: user.id, tenantId: user.jewelryId, meta: { jti: String(payload.jti) } });
    return res.json({ ok: true });
  } catch {
    auditLog(req, { action: "auth.reset_password", success: false, meta: { reason: "jwt_verify_failed" } });
    return res.status(401).json({ message: "Token inválido." });
  }
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
