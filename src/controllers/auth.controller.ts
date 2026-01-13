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
    if (ov.effect === OverrideEffect.ALLOW) allow.push(p);
    if (ov.effect === OverrideEffect.DENY) deny.push(p);
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
 * Construye base pública para URLs de archivos.
 * - Si seteás PUBLIC_BASE_URL en env (recomendado en prod), lo usa.
 * - Si no, usa protocolo + host del request.
 */
function publicBaseUrl(req: Request) {
  const envBase = process.env.PUBLIC_BASE_URL?.replace(/\/+$/, "");
  if (envBase) return envBase;
  return `${req.protocol}://${req.get("host")}`;
}

/** extrae filename de multer (diskStorage) */
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

/* =========================
   DB SELECTS (performance)
========================= */

// ✅ OJO: en Prisma no podés mezclar "select" con "include".
//     Dejamos TODO en select para que compile y sea consistente.
const authUserSelect = {
  id: true,
  email: true,
  name: true,
  status: true,
  avatarUrl: true,
  jewelryId: true,
  tokenVersion: true,
  createdAt: true,
  updatedAt: true,

  jewelry: {
    select: {
      id: true,
      name: true,
      firstName: true,
      lastName: true,
      phoneCountry: true,
      phoneNumber: true,
      street: true,
      number: true,
      city: true,
      province: true,
      postalCode: true,
      country: true,
      legalName: true,
      cuit: true,
      ivaCondition: true,
      email: true,
      website: true,
      notes: true,
      logoUrl: true,
      createdAt: true,
      updatedAt: true,
      attachments: true, // si tu schema tiene JewelryAttachment via relation
    } as any,
  },

  favoriteWarehouse: {
    select: {
      id: true,
      name: true,
    } as any,
  },

  roles: {
    select: {
      roleId: true,
      role: {
        select: {
          id: true,
          name: true, // técnico (OWNER/ADMIN/...)
          displayName: true, // visible
          isSystem: true,
          deletedAt: true,
          permissions: {
            select: {
              permission: { select: { module: true, action: true } },
            },
          },
        },
      },
    },
  },

  permissionOverrides: {
    select: {
      effect: true,
      permission: { select: { module: true, action: true } },
    },
  },
} as const;

function mapRolesForClient(user: any) {
  return (user.roles ?? [])
    .map((ur: any) => {
      const r = ur.role;
      if (!r) return null;
      return {
        id: r.id,
        name: r.displayName ?? r.name, // ✅ visible
        code: r.name, // ✅ técnico
        isSystem: r.isSystem ?? false,
      };
    })
    .filter(Boolean);
}

/* =========================
   ME
========================= */
export async function me(req: Request, res: Response) {
  const userId = (req as any).userId;
  const tenantId = (req as any).tenantId;

  if (!userId || !tenantId) return res.status(401).json({ message: "Unauthorized" });

  // ✅ Seguridad multi-tenant: filtramos también por jewelryId
  const user = await prisma.user.findFirst({
    where: { id: userId, jewelryId: tenantId },
    select: authUserSelect as any,
  });

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

  const roles = mapRolesForClient(user);
  const permissions = computeEffectivePermissions(user as any);

  // ✅ user “safe” explícito (evita filtrar cosas de más)
  const safeUser = {
    id: user.id,
    email: user.email,
    name: user.name,
    avatarUrl: user.avatarUrl,
    status: user.status,
    jewelryId: user.jewelryId,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };

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
   - soporta logo + attachments via multer fields:
     - logo (1)
     - attachments (N)
     - attachments[] (N) ✅
========================= */
export async function updateMyJewelry(req: Request, res: Response) {
  const userId = (req as any).userId as string;
  const data = req.body as any;

  const meUser = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!meUser) return res.status(404).json({ message: "User not found." });
  if (!meUser.jewelryId) return res.status(400).json({ message: "Jewelry not set for user." });

  // multer fields()
  const files = (req as any).files as
    | {
        logo?: Array<{ filename: string; originalname: string; mimetype: string; size: number }>;
        attachments?: Array<{
          filename: string;
          originalname: string;
          mimetype: string;
          size: number;
        }>;
        "attachments[]"?: Array<{
          filename: string;
          originalname: string;
          mimetype: string;
          size: number;
        }>;
      }
    | undefined;

  const logoFile = files?.logo?.[0] ?? null;

  // ✅ robusto: si llegan ambos, se unen
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
    ...(newLogoUrl ? { logoUrl: newLogoUrl } : { logoUrl: s(data.logoUrl) }),
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

  // ✅ devolver SIEMPRE attachments (si existe el modelo)
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

    return res.json({ ...(jewelry ?? updated), attachments: atts });
  } catch {
    return res.json(updated);
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
    // si el schema no tiene logoUrl, no rompemos
  }

  if (prevFilename) await tryDeleteUploadFile(prevFilename);

  auditLog(req, {
    action: "jewelry.delete_logo",
    success: true,
    userId,
    tenantId: meUser.jewelryId,
  });

  return res.status(204).send();
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

    return res.status(204).send();
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

  const existing = await prisma.user.findUnique({ where: { email } });
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
        data: {
          name: r.name,
          jewelryId: jewelry.id,
          isSystem: r.isSystem,
        },
      });

      if (r.name === "OWNER") ownerRoleId = role.id;

      await tx.rolePermission.createMany({
        data: r.permIds.map((permissionId) => ({
          roleId: role.id,
          permissionId,
        })),
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
      select: authUserSelect as any,
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

  const roles = mapRolesForClient(result.user);
  const permissions = computeEffectivePermissions(result.user as any);

  const safeUser = {
    id: result.user.id,
    email: result.user.email,
    name: result.user.name,
    avatarUrl: result.user.avatarUrl,
    status: result.user.status,
    jewelryId: result.user.jewelryId,
    createdAt: result.user.createdAt,
    updatedAt: result.user.updatedAt,
  };

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

  // ✅ select liviano (evita include gigante)
  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      ...(authUserSelect as any),
      password: true, // ✅ solo acá lo pedimos
    },
  });

  if (!user) {
    auditLog(req, {
      action: "auth.login",
      success: false,
      meta: { email, reason: "user_not_found" },
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

  const roles = mapRolesForClient(user);
  const permissions = computeEffectivePermissions(user as any);

  const safeUser = {
    id: user.id,
    email: user.email,
    name: user.name,
    avatarUrl: user.avatarUrl,
    status: user.status,
    jewelryId: user.jewelryId,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };

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

  return res.status(204).send();
}

/* =========================
   FORGOT PASSWORD
========================= */
export async function forgotPassword(req: Request, res: Response) {
  const data = req.body as any;
  const email = s(data.email).toLowerCase();

  const user = await prisma.user.findUnique({ where: { email } });

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
