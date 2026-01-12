// BACKEND
// src/controllers/auth.controller.ts
import type { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
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

/* =========================
   ME
========================= */
export async function me(req: Request, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ message: "Unauthorized" });

  const user = await prisma.user.findUnique({
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
      permissionOverrides: {
        include: { permission: true },
      },
    },
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

  const safeUser: any = { ...user };
  delete safeUser.password;

  const roles = (user.roles ?? []).map((ur) => ({
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
   - guarda campos "vacíos" también
   - soporta logo + attachments via multer fields:
     - logo (1)
     - attachments (N)
========================= */
export async function updateMyJewelry(req: Request, res: Response) {
  const userId = req.userId!;
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
        logo?: Express.Multer.File[];
        attachments?: Express.Multer.File[];
      }
    | undefined;

  const logoFile = files?.logo?.[0] ?? null;
  const attachments = files?.attachments ?? [];

  // Si subieron logo, generamos URL pública
  const newLogoUrl = logoFile ? fileUrl(req, logoFile.filename) : undefined;

  // 1) Update de Jewelry (incluye campos "empresa" + los existentes)
  // ⚠️ Si alguno de estos campos todavía NO existe en tu schema.prisma,
  // Prisma va a fallar al compilar. En ese caso agregalos (te dejo abajo el schema).
  const updated = await prisma.jewelry.update({
    where: { id: meUser.jewelryId },
    data: {
      // existentes
      name: s(data.name),
      phoneCountry: s(data.phoneCountry),
      phoneNumber: s(data.phoneNumber),
      street: s(data.street),
      number: s(data.number),
      city: s(data.city),
      province: s(data.province),
      postalCode: s(data.postalCode),
      country: s(data.country),

      // nuevos (empresa)
      legalName: s(data.legalName),
      cuit: s(data.cuit),
      ivaCondition: s(data.ivaCondition),
      email: s(data.email),
      website: s(data.website),
      notes: String(data.notes ?? ""),

      // logoUrl: solo si subieron archivo, si no mantenemos lo que venga por body (compatibilidad)
      ...(newLogoUrl
        ? { logoUrl: newLogoUrl }
        : { logoUrl: s(data.logoUrl) }),
    } as any,
  });

  // 2) Persistencia de adjuntos (si existe el modelo JewelryAttachment)
  // Si todavía no lo tenés, agregalo al schema (abajo) y migrá.
  if (attachments.length > 0) {
    // Evitar crash si todavía no existe el modelo:
    // si no existe, TypeScript/Prisma te va a avisar en build.
    await prisma.jewelryAttachment.createMany({
      data: attachments.map((f) => ({
        jewelryId: meUser.jewelryId!,
        url: fileUrl(req, f.filename),
        filename: f.originalname,
        mimeType: f.mimetype,
        size: f.size,
      })),
      skipDuplicates: true,
    });
  }

  // 3) Devolver joyería + adjuntos para refrescar UI
  const jewelryWithAttachments = await prisma.jewelry.findUnique({
    where: { id: meUser.jewelryId },
    include: {
      attachments: true, // relación JewelryAttachment[]
    } as any,
  });

  auditLog(req, {
    action: "jewelry.update_profile",
    success: true,
    userId,
    tenantId: meUser.jewelryId,
    meta: {
      logoUploaded: !!logoFile,
      attachmentsUploaded: attachments.length,
    },
  });

  return res.json(jewelryWithAttachments ?? updated);
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
    // 1) crear joyería
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

    // 2) asegurar catálogo global Permission (idempotente)
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

    // 3) crear roles system + permisos (para ESTA joyería nueva)
    let ownerRoleId = "";
    for (const r of rolesToCreate) {
      const role = await tx.role.create({
        data: {
          name: r.name,
          jewelryId: jewelry.id,
          isSystem: r.isSystem,
          permIds: undefined as any,
        } as any,
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

    // 4) crear usuario
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

    // 5) asignar OWNER
    await tx.userRole.create({
      data: {
        userId: user.id,
        roleId: ownerRoleId,
      },
    });

    // 6) traer user completo para devolver roles/perms reales
    const fullUser = await tx.user.findUniqueOrThrow({
      where: { id: user.id },
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

  const roles = (result.user.roles ?? []).map((ur) => ({
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

  const user = await prisma.user.findUnique({
    where: { email },
    include: {
      jewelry: true,
      roles: {
        include: {
          role: {
            include: {
              permissions: { include: { permission: true } },
            },
          },
        },
      },
      permissionOverrides: {
        include: { permission: true },
      },
      favoriteWarehouse: true,
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

  const safeUser: any = { ...user };
  delete safeUser.password;

  const roles = (user.roles ?? []).map((ur) => ({
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
    userId: req.userId,
    tenantId: req.tenantId,
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

  // ✅ no filtramos info
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
        tokenVersion: { increment: 1 }, // ✅ invalida sesiones previas
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
