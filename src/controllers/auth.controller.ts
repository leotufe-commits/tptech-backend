// tptech-backend/src/controllers/auth.controller.ts
import type { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { prisma } from "../lib/prisma.js";
import { sendResetEmail } from "../lib/mailer.js";
import { UserStatus, OverrideEffect, PermModule, PermAction } from "@prisma/client";
import { auditLog } from "../lib/auditLogger.js";

/* =========================
   ENV / CONST
========================= */
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error("❌ JWT_SECRET no está configurado");
const JWT_SECRET_SAFE: string = JWT_SECRET;

const APP_URL = process.env.APP_URL || "http://localhost:5174";

const JWT_ISSUER = process.env.JWT_ISSUER || "tptech";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "tptech-web";

// nombre único de cookie
const AUTH_COOKIE = "tptech_session";

/* =========================
   HELPERS
========================= */
type AccessTokenPayload = {
  sub: string;
  tenantId: string;
  tokenVersion: number;
};

function signToken(userId: string, tenantId: string, tokenVersion: number) {
  const payload: AccessTokenPayload = { sub: userId, tenantId, tokenVersion };

  return jwt.sign(payload, JWT_SECRET_SAFE, {
    expiresIn: "7d",
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  });
}

/**
 * ✅ Política SIMPLE y correcta:
 * - DEV (localhost / http):  sameSite="lax",  secure=false
 * - PROD (Render / https):   sameSite="none", secure=true
 */
function setAuthCookie(_req: Request, res: Response, token: string) {
  const isProd = process.env.NODE_ENV === "production";

  res.cookie(AUTH_COOKIE, token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
  });
}

function clearAuthCookie(_req: Request, res: Response) {
  const isProd = process.env.NODE_ENV === "production";

  res.clearCookie(AUTH_COOKIE, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
    path: "/",
  });
}

function uniq(arr: string[]) {
  return Array.from(new Set(arr));
}

function formatPerm(module: string, action: string) {
  return `${module}:${action}`;
}

type ComputeUserShape = {
  roles: Array<{
    role: {
      permissions: Array<{ permission: { module: any; action: any } }>;
    };
  }>;
  permissionOverrides: Array<{
    effect: OverrideEffect;
    permission: { module: any; action: any };
  }>;
};

function computeEffectivePermissions(user: ComputeUserShape) {
  // 1) permisos por roles
  const fromRoles: string[] = [];
  for (const ur of user.roles ?? []) {
    const rps = ur.role?.permissions ?? [];
    for (const rp of rps) {
      fromRoles.push(formatPerm(String(rp.permission.module), String(rp.permission.action)));
    }
  }

  // 2) overrides
  const allow: string[] = [];
  const deny: string[] = [];
  for (const ov of user.permissionOverrides ?? []) {
    const p = formatPerm(String(ov.permission.module), String(ov.permission.action));
    if (ov.effect === "ALLOW") allow.push(p);
    if (ov.effect === "DENY") deny.push(p);
  }

  // 3) aplicar deny sobre roles y allow
  const base = new Set(uniq(fromRoles));
  for (const d of deny) base.delete(d);
  for (const a of allow) base.add(a);
  for (const d of deny) base.delete(d);

  return Array.from(base).sort();
}

// ✅ normalizador: SIEMPRE string (incluye "")
const s = (v: any) => String(v ?? "").trim();

/**
 * Cuando viene multipart/form-data:
 * - el frontend manda: fd.append("data", JSON.stringify(payload))
 * - Express/Multer deja req.body.data como string
 * Este helper normaliza ambos casos (JSON puro o multipart).
 */
function parseBodyData(req: Request) {
  const b: any = (req as any).body ?? {};
  if (b && typeof b === "object" && typeof b.data === "string" && b.data.trim()) {
    try {
      const parsed = JSON.parse(b.data);
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      return {};
    }
  }
  return b && typeof b === "object" ? b : {};
}

/**
 * Construye base pública para URLs de archivos.
 * - Si seteás PUBLIC_BASE_URL en env (recomendado en prod), lo usa.
 * - Si no, usa protocolo + host del request.
 */
function publicBaseUrl(req: Request) {
  const envBase = process.env.PUBLIC_BASE_URL?.replace(/\/+$/, "");
  if (envBase) return envBase;
  return `${req.protocol}://${req.get("host")}`;
}

/** URL pública del archivo subido */
function fileUrl(req: Request, filename: string) {
  return `${publicBaseUrl(req)}/uploads/jewelry/${encodeURIComponent(filename)}`;
}

function filenameFromPublicUrl(url: string) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split("/");
    return decodeURIComponent(parts[parts.length - 1] || "");
  } catch {
    const parts = String(url || "").split("/");
    return decodeURIComponent(parts[parts.length - 1] || "");
  }
}

async function tryDeleteUploadFile(storageFilename: string) {
  if (!storageFilename) return;

  const safe = path.basename(storageFilename); // evita ../
  if (!safe) return;

  const p = path.join(process.cwd(), "uploads", "jewelry", safe);
  try {
    await fs.promises.unlink(p);
  } catch {
    // no-op
  }
}

/**
 * ✅ COMPAT: busca usuario por email aunque el schema sea:
 * - email @unique  => findUnique({ email })
 * - @@unique([jewelryId,email]) (compound) => findFirst({ where: { email } })
 *
 * Importante:
 * - Si en algún momento permitís el MISMO email en varias joyerías,
 *   este método devolverá el primero (por createdAt asc).
 *   Para hacerlo 100% multi-tenant, el login debe incluir jewelryId (o “código de empresa”).
 */
async function findUserByEmailCompat(email: string) {
  // 1) intentamos findUnique({ email }) (solo funciona si email es unique global)
  try {
    return await prisma.user.findUnique({
      where: { email } as any,
      include: {
        jewelry: true,
        roles: {
          include: {
            role: { include: { permissions: { include: { permission: true } } } },
          },
        },
        permissionOverrides: { include: { permission: true } },
        favoriteWarehouse: true,
      },
    });
  } catch {
    // 2) fallback: schema con compound unique (jewelryId_email)
    return await prisma.user.findFirst({
      where: { email, deletedAt: null },
      include: {
        jewelry: true,
        roles: {
          include: {
            role: { include: { permissions: { include: { permission: true } } } },
          },
        },
        permissionOverrides: { include: { permission: true } },
        favoriteWarehouse: true,
      },
      orderBy: { createdAt: "asc" },
    });
  }
}

/* =========================
   ME
========================= */
export async function me(req: Request, res: Response) {
  const userId = (req as any).userId as string | undefined;
  if (!userId) return res.status(401).json({ message: "Unauthorized" });

  let user: any = null;

  // 1) Intento: incluir attachments si el schema lo soporta
  try {
    user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        jewelry: { include: { attachments: true } } as any,
        favoriteWarehouse: true,
        roles: {
          include: {
            role: {
              include: {
                permissions: { include: { permission: true } },
              },
            },
          },
        },
        permissionOverrides: { include: { permission: true } },
      },
    });
  } catch {
    // 2) Fallback: schema sin attachments
    user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        jewelry: true,
        favoriteWarehouse: true,
        roles: {
          include: {
            role: {
              include: {
                permissions: { include: { permission: true } },
              },
            },
          },
        },
        permissionOverrides: { include: { permission: true } },
      },
    });
  }

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

  const safeUser: any = { ...user };
  delete safeUser.password;

  const roles = (user.roles ?? []).map((ur: any) => ({
    id: ur.roleId,
    name: ur.role?.name,
    isSystem: ur.role?.isSystem ?? false,
  }));

  const permissions = computeEffectivePermissions(user as any);

  delete safeUser.roles;
  delete safeUser.permissionOverrides;

  return res.json({
    user: safeUser,
    jewelry: user.jewelry ?? null,
    roles,
    permissions,
    favoriteWarehouse: user.favoriteWarehouse ?? null,
  });
}

/* =========================
   UPDATE JEWELRY (JSON + multipart)
========================= */
export async function updateMyJewelry(req: Request, res: Response) {
  const userId = (req as any).userId as string;
  const data = parseBodyData(req);

  const meUser = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!meUser) return res.status(404).json({ message: "User not found." });
  if (!meUser.jewelryId) return res.status(400).json({ message: "Jewelry not set for user." });

  const files = (req as any).files as
    | {
        logo?: Array<{ filename: string; originalname: string; mimetype: string; size: number }>;
        attachments?: Array<{ filename: string; originalname: string; mimetype: string; size: number }>;
        "attachments[]"?: Array<{ filename: string; originalname: string; mimetype: string; size: number }>;
      }
    | undefined;

  const logoFile = files?.logo?.[0] ?? null;
  const attachments = [...(files?.attachments ?? []), ...(files?.["attachments[]"] ?? [])];
  const newLogoUrl = logoFile ? fileUrl(req, logoFile.filename) : undefined;

  const baseUpdateData: any = {
    name: s(data.name),
    phoneCountry: s(data.phoneCountry),
    phoneNumber: s(data.phoneNumber),
    street: s(data.street),
    number: s(data.number),
    city: s(data.city),
    province: s(data.province),
    postalCode: s(data.postalCode),
    country: s(data.country),
  };

  const extendedUpdateData: any = {
    ...baseUpdateData,
    legalName: s(data.legalName),
    cuit: s(data.cuit),
    ivaCondition: s(data.ivaCondition),
    email: s(data.email),
    website: s(data.website),
    notes: String(data.notes ?? ""),
    ...(newLogoUrl ? { logoUrl: newLogoUrl } : { logoUrl: s((data as any).logoUrl) }),
  };

  let updated: any = null;

  try {
    updated = await prisma.jewelry.update({
      where: { id: meUser.jewelryId },
      data: extendedUpdateData,
    } as any);
  } catch {
    updated = await prisma.jewelry.update({
      where: { id: meUser.jewelryId },
      data: baseUpdateData,
    } as any);
  }

  if (attachments.length > 0) {
    try {
      await (prisma as any).jewelryAttachment.createMany({
        data: attachments.map((f) => ({
          jewelryId: meUser.jewelryId,
          url: fileUrl(req, f.filename),
          filename: f.originalname,
          mimeType: f.mimetype,
          size: f.size,
        })),
        skipDuplicates: true,
      });
    } catch (e) {
      console.error("❌ jewelryAttachment.createMany failed:", e);
    }
  }

  try {
    const jewelry = await prisma.jewelry.findUnique({
      where: { id: meUser.jewelryId },
    });

    let atts: any[] = [];
    try {
      atts = await (prisma as any).jewelryAttachment.findMany({
        where: { jewelryId: meUser.jewelryId },
        orderBy: { createdAt: "desc" },
      });
    } catch {
      atts = [];
    }

    auditLog(req, {
      action: "jewelry.update_profile",
      success: true,
      userId,
      tenantId: meUser.jewelryId,
      meta: { logoUploaded: !!logoFile, attachmentsUploaded: attachments.length },
    });

    return res.json({
      jewelry: {
        ...(jewelry ?? updated),
        attachments: atts,
      },
    });
  } catch {
    return res.json({ jewelry: updated });
  }
}

/* =========================
   DELETE JEWELRY LOGO
========================= */
export async function deleteMyJewelryLogo(req: Request, res: Response) {
  const userId = (req as any).userId as string;

  const meUser = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!meUser) return res.status(404).json({ message: "User not found." });
  if (!meUser.jewelryId) return res.status(400).json({ message: "Jewelry not set for user." });

  const jewelry = await prisma.jewelry.findUnique({
    where: { id: meUser.jewelryId },
    select: { logoUrl: true } as any,
  });

  const prevUrl = (jewelry as any)?.logoUrl || "";
  const prevFilename = prevUrl ? filenameFromPublicUrl(prevUrl) : "";

  try {
    await prisma.jewelry.update({
      where: { id: meUser.jewelryId },
      data: { logoUrl: "" } as any,
    });
  } catch {
    // ignore
  }

  if (prevFilename) await tryDeleteUploadFile(prevFilename);

  auditLog(req, {
    action: "jewelry.delete_logo",
    success: true,
    userId,
    tenantId: meUser.jewelryId,
  });

  return res.json({ ok: true });
}

/* =========================
   DELETE JEWELRY ATTACHMENT
========================= */
export async function deleteMyJewelryAttachment(req: Request, res: Response) {
  const userId = (req as any).userId as string;
  const attachmentId = String(req.params.id || "").trim();

  if (!attachmentId) return res.status(400).json({ message: "ID inválido." });

  const meUser = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!meUser) return res.status(404).json({ message: "User not found." });
  if (!meUser.jewelryId) return res.status(400).json({ message: "Jewelry not set for user." });

  try {
    const att = await (prisma as any).jewelryAttachment.findUnique({
      where: { id: attachmentId },
      select: { id: true, jewelryId: true, url: true },
    });

    if (!att || att.jewelryId !== meUser.jewelryId) {
      return res.status(404).json({ message: "Adjunto no encontrado." });
    }

    const storageFilename = filenameFromPublicUrl(att.url);

    await (prisma as any).jewelryAttachment.delete({
      where: { id: attachmentId },
    });

    if (storageFilename) await tryDeleteUploadFile(storageFilename);

    auditLog(req, {
      action: "jewelry.delete_attachment",
      success: true,
      userId,
      tenantId: meUser.jewelryId,
      meta: { attachmentId },
    });

    return res.json({ ok: true });
  } catch {
    return res.status(404).json({ message: "Adjunto no encontrado." });
  }
}

/* =========================
   REGISTER
========================= */
export async function register(req: Request, res: Response) {
  const data = req.body as any;
  const email = s(data.email).toLowerCase();

  // ✅ Compat: si email es unique global => findUnique funciona
  // ✅ Si NO es unique global => evitamos duplicados igual (para no romper login por email)
  const existing = await prisma.user.findFirst({
    where: { email, deletedAt: null },
    select: { id: true },
  });

  if (existing) {
    auditLog(req, {
      action: "auth.register",
      success: false,
      meta: { email, reason: "email_already_registered" },
    });
    return res.status(409).json({ message: "El email ya está registrado." });
  }

  const hashed = await bcrypt.hash(String(data.password ?? ""), 10);

  const ALL_MODULES = Object.values(PermModule);
  const ALL_ACTIONS = Object.values(PermAction);

  const result = await prisma.$transaction(async (tx) => {
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
    for (const module of ALL_MODULES) {
      for (const action of ALL_ACTIONS) {
        permissionsData.push({ module, action });
      }
    }

    await tx.permission.createMany({
      data: permissionsData,
      skipDuplicates: true,
    });

    const allPermissions = await tx.permission.findMany();
    const permIdByKey = new Map<string, string>();
    for (const p of allPermissions) permIdByKey.set(`${p.module}:${p.action}`, p.id);

    const pick = (modules: PermModule[], actions: PermAction[]) => {
      const ids: string[] = [];
      for (const m of modules) {
        for (const a of actions) {
          const id = permIdByKey.get(`${m}:${a}`);
          if (id) ids.push(id);
        }
      }
      return ids;
    };

    const OWNER_PERMS = allPermissions.map((p) => p.id);
    const ADMIN_PERMS = pick(ALL_MODULES as PermModule[], ALL_ACTIONS as PermAction[]);
    const STAFF_PERMS = pick(ALL_MODULES as PermModule[], [
      PermAction.VIEW,
      PermAction.CREATE,
      PermAction.EDIT,
    ]);
    const READONLY_PERMS = pick(ALL_MODULES as PermModule[], [PermAction.VIEW]);

    const rolesToCreate = [
      { name: "OWNER", isSystem: true, permIds: OWNER_PERMS },
      { name: "ADMIN", isSystem: true, permIds: ADMIN_PERMS },
      { name: "STAFF", isSystem: true, permIds: STAFF_PERMS },
      { name: "READONLY", isSystem: true, permIds: READONLY_PERMS },
    ] as const;

    let ownerRoleId = "";
    for (const r of rolesToCreate) {
      const role = await tx.role.create({
        data: { name: r.name, jewelryId: jewelry.id, isSystem: r.isSystem },
      });
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

    await tx.userRole.create({
      data: { userId: user.id, roleId: ownerRoleId },
    });

    const fullUser = await tx.user.findUniqueOrThrow({
      where: { id: user.id },
      include: {
        jewelry: true,
        favoriteWarehouse: true,
        roles: { include: { role: { include: { permissions: { include: { permission: true } } } } } },
        permissionOverrides: { include: { permission: true } },
      },
    });

    return { user: fullUser, jewelry };
  });

  const token = signToken(result.user.id, result.user.jewelryId, result.user.tokenVersion);
  setAuthCookie(req, res, token);

  auditLog(req, {
    action: "auth.register",
    success: true,
    userId: result.user.id,
    tenantId: result.user.jewelryId,
    meta: { email },
  });

  const safeUser: any = { ...result.user };
  delete safeUser.password;

  const roles = (result.user.roles ?? []).map((ur: any) => ({
    id: ur.roleId,
    name: ur.role?.name,
    isSystem: ur.role?.isSystem ?? false,
  }));

  const permissions = computeEffectivePermissions(result.user as any);

  delete safeUser.roles;
  delete safeUser.permissionOverrides;

  return res.status(201).json({
    user: safeUser,
    jewelry: result.jewelry,
    roles,
    permissions,
    favoriteWarehouse: result.user.favoriteWarehouse ?? null,
    token,
    accessToken: token,
  });
}

/* =========================
   LOGIN
========================= */
export async function login(req: Request, res: Response) {
  const data = req.body as any;
  const email = s(data.email).toLowerCase();
  const password = String(data.password ?? "");

  const user = await findUserByEmailCompat(email);

  if (!user) {
    auditLog(req, {
      action: "auth.login",
      success: false,
      meta: { email, reason: "user_not_found" },
    });
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  if (user.deletedAt) {
    auditLog(req, {
      action: "auth.login",
      success: false,
      userId: user.id,
      tenantId: user.jewelryId,
      meta: { email, reason: "user_deleted" },
    });
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  if (user.status !== UserStatus.ACTIVE) {
    auditLog(req, {
      action: "auth.login",
      success: false,
      userId: user.id,
      tenantId: user.jewelryId,
      meta: { email, reason: "user_blocked" },
    });
    return res.status(403).json({ message: "Usuario no habilitado." });
  }

  if (!password) {
    auditLog(req, {
      action: "auth.login",
      success: false,
      userId: user.id,
      tenantId: user.jewelryId,
      meta: { email, reason: "empty_password" },
    });
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
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
  });

  const safeUser: any = { ...user };
  delete safeUser.password;

  const roles = (user.roles ?? []).map((ur: any) => ({
    id: ur.roleId,
    name: ur.role?.name,
    isSystem: ur.role?.isSystem ?? false,
  }));

  const permissions = computeEffectivePermissions(user as any);

  delete safeUser.roles;
  delete safeUser.permissionOverrides;

  return res.json({
    user: safeUser,
    jewelry: user.jewelry ?? null,
    roles,
    permissions,
    favoriteWarehouse: user.favoriteWarehouse ?? null,
    token,
    accessToken: token,
  });
}

/* =========================
   LOGOUT
========================= */
export async function logout(req: Request, res: Response) {
  clearAuthCookie(req, res);

  auditLog(req, {
    action: "auth.logout",
    success: true,
    userId: (req as any).userId,
    tenantId: (req as any).tenantId,
  });

  // ✅ mejor que 204 para evitar parseo JSON en apiFetch
  return res.json({ ok: true });
}

/* =========================
   FORGOT PASSWORD
========================= */
export async function forgotPassword(req: Request, res: Response) {
  const data = req.body as any;
  const email = s(data.email).toLowerCase();

  // ✅ Compat: no asumir email unique global
  const user = await prisma.user.findFirst({
    where: { email, deletedAt: null },
    select: { id: true, jewelryId: true },
    orderBy: { createdAt: "asc" },
  });

  if (!user) {
    auditLog(req, {
      action: "auth.forgot_password",
      success: true,
      meta: { email, userFound: false },
    });
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
   RESET PASSWORD
========================= */
export async function resetPassword(req: Request, res: Response) {
  const data = req.body as any;

  try {
    const payload = jwt.verify(String(data.token), JWT_SECRET_SAFE, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    }) as any;

    if (!payload?.sub || payload?.type !== "reset" || !payload?.jti) {
      auditLog(req, {
        action: "auth.reset_password",
        success: false,
        meta: { reason: "invalid_token_payload" },
      });
      return res.status(401).json({ message: "Token inválido." });
    }

    const userId = String(payload.sub);

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, jewelryId: true },
    });

    if (!user) {
      auditLog(req, {
        action: "auth.reset_password",
        success: false,
        meta: { reason: "user_not_found" },
      });
      return res.status(401).json({ message: "Token inválido." });
    }

    const newHash = await bcrypt.hash(String(data.newPassword ?? ""), 10);

    await prisma.user.update({
      where: { id: userId },
      data: {
        password: newHash,
        tokenVersion: { increment: 1 },
      },
    });

    clearAuthCookie(req, res);

    auditLog(req, {
      action: "auth.reset_password",
      success: true,
      userId: user.id,
      tenantId: user.jewelryId,
      meta: { jti: String(payload.jti) },
    });

    return res.json({ ok: true });
  } catch {
    auditLog(req, {
      action: "auth.reset_password",
      success: false,
      meta: { reason: "jwt_verify_failed" },
    });
    return res.status(401).json({ message: "Token inválido." });
  }
}

/* =========================
   PIN (solo dentro del sistema)
   - Unlock por PIN
   - Quick Switch por PIN (configurable por joyería)
========================= */

function isValidPin(pin: any) {
  const p = String(pin ?? "").trim();
  return /^\d{4}$/.test(p);
}

/** Requiere que el usuario actual exista y sea ACTIVE */
async function requireActiveMe(req: Request) {
  const userId = (req as any).userId as string | undefined;
  if (!userId) return null;

  const meUser = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      status: true,
      jewelryId: true,
      quickPinHash: true,
      quickPinEnabled: true,
      quickPinUpdatedAt: true,
      quickPinFailedCount: true,
      quickPinLockedUntil: true,
    },
  });

  if (!meUser) return null;
  if (meUser.status !== UserStatus.ACTIVE) return null;
  return meUser;
}

/** Lee si la joyería permite quick switch */
async function isQuickSwitchEnabled(jewelryId: string) {
  try {
    const j = await prisma.jewelry.findUnique({
      where: { id: jewelryId },
      select: { quickSwitchEnabled: true } as any,
    });
    return !!(j as any)?.quickSwitchEnabled;
  } catch {
    return false;
  }
}

/* ---------- SET PIN (crear/cambiar) ---------- */
export async function setMyPin(req: Request, res: Response) {
  const meUser = await requireActiveMe(req);
  if (!meUser) return res.status(401).json({ message: "Unauthorized" });

  const pin = String((req.body as any)?.pin ?? "").trim();
  if (!isValidPin(pin)) return res.status(400).json({ message: "El PIN debe tener 4 dígitos." });

  const quickPinHash = await bcrypt.hash(pin, 10);

  await prisma.user.update({
    where: { id: meUser.id },
    data: {
      quickPinHash,
      quickPinEnabled: true,
      quickPinUpdatedAt: new Date(),
      quickPinFailedCount: 0,
      quickPinLockedUntil: null,
      tokenVersion: { increment: 1 },
    },
  });

  auditLog(req, {
    action: "auth.pin_set",
    success: true,
    userId: meUser.id,
    tenantId: meUser.jewelryId,
  });

  return res.json({ ok: true });
}

/* ---------- DISABLE PIN ---------- */
export async function disableMyPin(req: Request, res: Response) {
  const meUser = await requireActiveMe(req);
  if (!meUser) return res.status(401).json({ message: "Unauthorized" });

  const pin = String((req.body as any)?.pin ?? "").trim();
  if (!isValidPin(pin)) return res.status(400).json({ message: "PIN inválido." });

  if (!meUser.quickPinEnabled || !meUser.quickPinHash) {
    return res.status(400).json({ message: "El PIN no está habilitado." });
  }

  const ok = await bcrypt.compare(pin, String(meUser.quickPinHash));
  if (!ok) {
    auditLog(req, {
      action: "auth.pin_disable",
      success: false,
      userId: meUser.id,
      tenantId: meUser.jewelryId,
      meta: { reason: "invalid_pin" },
    });
    return res.status(401).json({ message: "PIN incorrecto." });
  }

  await prisma.user.update({
    where: { id: meUser.id },
    data: {
      quickPinHash: null,
      quickPinEnabled: false,
      quickPinUpdatedAt: new Date(),
      quickPinFailedCount: 0,
      quickPinLockedUntil: null,
      tokenVersion: { increment: 1 },
    },
  });

  auditLog(req, {
    action: "auth.pin_disable",
    success: true,
    userId: meUser.id,
    tenantId: meUser.jewelryId,
  });

  return res.json({ ok: true });
}

/* ---------- UNLOCK ---------- */
export async function unlockWithPin(req: Request, res: Response) {
  const meUser = await requireActiveMe(req);
  if (!meUser) return res.status(401).json({ message: "Unauthorized" });

  const pin = String((req.body as any)?.pin ?? "").trim();
  if (!isValidPin(pin)) return res.status(400).json({ message: "PIN inválido." });

  if (!meUser.quickPinEnabled || !meUser.quickPinHash) {
    return res.status(400).json({ message: "Este usuario no tiene PIN configurado." });
  }

  const ok = await bcrypt.compare(pin, String(meUser.quickPinHash));
  if (!ok) {
    auditLog(req, {
      action: "auth.pin_unlock",
      success: false,
      userId: meUser.id,
      tenantId: meUser.jewelryId,
      meta: { reason: "invalid_pin" },
    });
    return res.status(401).json({ message: "PIN incorrecto." });
  }

  await prisma.user.update({
    where: { id: meUser.id },
    data: {
      quickPinFailedCount: 0,
      quickPinLockedUntil: null,
      quickPinUpdatedAt: new Date(),
    },
  });

  auditLog(req, {
    action: "auth.pin_unlock",
    success: true,
    userId: meUser.id,
    tenantId: meUser.jewelryId,
  });

  return res.json({ ok: true });
}

/* ---------- QUICK USERS ---------- */
export async function quickUsers(req: Request, res: Response) {
  const meUser = await requireActiveMe(req);
  if (!meUser) return res.status(401).json({ message: "Unauthorized" });

  const enabled = await isQuickSwitchEnabled(meUser.jewelryId);
  if (!enabled) return res.json({ enabled: false, users: [] });

  const users = await prisma.user.findMany({
    where: {
      jewelryId: meUser.jewelryId,
      status: UserStatus.ACTIVE,
      deletedAt: null,
      quickPinEnabled: true,
    },
    select: {
      id: true,
      email: true,
      name: true,
      avatarUrl: true,
      quickPinEnabled: true,
    },
    orderBy: { createdAt: "asc" },
  });

  return res.json({
    enabled: true,
    users: users.map((u) => ({
      id: u.id,
      email: u.email,
      name: u.name,
      avatarUrl: u.avatarUrl,
      hasPin: Boolean(u.quickPinEnabled),
    })),
  });
}

/* ---------- SWITCH USER ---------- */
export async function switchUserWithPin(req: Request, res: Response) {
  const meUser = await requireActiveMe(req);
  if (!meUser) return res.status(401).json({ message: "Unauthorized" });

  const enabled = await isQuickSwitchEnabled(meUser.jewelryId);
  if (!enabled) {
    return res.status(403).json({ message: "Cambio rápido de usuario deshabilitado." });
  }

  const targetUserId = String((req.body as any)?.targetUserId ?? "").trim();
  const pin = String((req.body as any)?.pin ?? "").trim();

  if (!targetUserId) return res.status(400).json({ message: "targetUserId requerido." });
  if (!isValidPin(pin)) return res.status(400).json({ message: "PIN inválido." });

  const target = await prisma.user.findUnique({
    where: { id: targetUserId },
    include: {
      jewelry: true,
      roles: {
        include: {
          role: { include: { permissions: { include: { permission: true } } } },
        },
      },
      permissionOverrides: { include: { permission: true } },
      favoriteWarehouse: true,
    },
  });

  if (!target || target.jewelryId !== meUser.jewelryId || target.deletedAt) {
    auditLog(req, {
      action: "auth.pin_switch",
      success: false,
      userId: meUser.id,
      tenantId: meUser.jewelryId,
      meta: { reason: "target_not_found_or_other_tenant", targetUserId },
    });
    return res.status(404).json({ message: "Usuario no encontrado." });
  }

  if (target.status !== UserStatus.ACTIVE) {
    return res.status(403).json({ message: "Usuario no habilitado." });
  }

  if (!target.quickPinEnabled || !target.quickPinHash) {
    return res.status(400).json({ message: "El usuario seleccionado no tiene PIN configurado." });
  }

  const ok = await bcrypt.compare(pin, String(target.quickPinHash));
  if (!ok) {
    auditLog(req, {
      action: "auth.pin_switch",
      success: false,
      userId: meUser.id,
      tenantId: meUser.jewelryId,
      meta: { reason: "invalid_pin", targetUserId },
    });
    return res.status(401).json({ message: "PIN incorrecto." });
  }

  const token = signToken(target.id, target.jewelryId, target.tokenVersion);
  setAuthCookie(req, res, token);

  auditLog(req, {
    action: "auth.pin_switch",
    success: true,
    userId: target.id,
    tenantId: target.jewelryId,
    meta: { fromUserId: meUser.id },
  });

  const safeUser: any = { ...target };
  delete safeUser.password;

  // ✅ nunca enviar secretos
  delete safeUser.quickPinHash;

  const roles = (target.roles ?? []).map((ur: any) => ({
    id: ur.roleId,
    name: ur.role?.name,
    isSystem: ur.role?.isSystem ?? false,
  }));

  const permissions = computeEffectivePermissions(target as any);

  delete safeUser.roles;
  delete safeUser.permissionOverrides;

  return res.json({
    user: safeUser,
    jewelry: target.jewelry ?? null,
    roles,
    permissions,
    favoriteWarehouse: target.favoriteWarehouse ?? null,
    token,
    accessToken: token,
  });
}
