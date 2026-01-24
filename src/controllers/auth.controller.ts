// tptech-backend/src/controllers/auth.controller.ts
import type { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { prisma } from "../lib/prisma.js";
import { sendResetEmail } from "../lib/mailer.js";
import { UserStatus, PermModule, PermAction } from "@prisma/client";
import type { Prisma, Permission as PermissionRow } from "@prisma/client";
import { auditLog } from "../lib/auditLogger.js";
import { buildAuthResponse } from "../lib/authResponse.js";

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

// ✅ normalizador: SIEMPRE string (incluye "")
const s = (v: unknown) => String(v ?? "").trim();

/**
 * Cuando viene multipart/form-data:
 * - el frontend manda: fd.append("data", JSON.stringify(payload))
 * - Express/Multer deja req.body.data como string
 * Este helper normaliza ambos casos (JSON puro o multipart).
 */
function parseBodyData(req: Request): Record<string, unknown> {
  const b = ((req as unknown as { body?: unknown }).body ?? {}) as any;

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

function isPrismaUniqueError(e: any) {
  return (
    e &&
    typeof e === "object" &&
    (e.code === "P2002" || e.name === "PrismaClientKnownRequestError")
  );
}

function prismaUniqueTargets(e: any): string[] {
  const t = e?.meta?.target;
  if (Array.isArray(t)) return t.map(String);
  if (typeof t === "string") return [t];
  return [];
}

/* =========================
   PRISMA INCLUDES (centralizado)
========================= */
const AUTH_USER_INCLUDE = {
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
} as const;

async function fetchUserForAuthById(userId: string) {
  return prisma.user.findUnique({
    where: { id: userId },
    include: AUTH_USER_INCLUDE,
  });
}

async function fetchUserForAuthByEmailAndTenant(email: string, tenantId: string) {
  return prisma.user.findFirst({
    where: { email, jewelryId: tenantId, deletedAt: null },
    include: AUTH_USER_INCLUDE,
    orderBy: { createdAt: "asc" },
  });
}

async function fetchUsersForLoginOptions(email: string) {
  const users = await prisma.user.findMany({
    where: { email, deletedAt: null },
    select: {
      jewelryId: true,
      jewelry: { select: { id: true, name: true } },
      createdAt: true,
    },
    orderBy: { createdAt: "asc" },
  });

  const map = new Map<string, { id: string; name: string }>();
  for (const u of users) {
    const j = (u as any).jewelry;
    if (j?.id && !map.has(j.id)) map.set(j.id, { id: j.id, name: j.name || "Joyería" });
  }
  return Array.from(map.values());
}

/* =========================
   ME (con fallback attachments encapsulado)
========================= */
async function fetchMeUserWithOptionalAttachments(userId: string) {
  // 1) Intento: include attachments si el schema lo soporta
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
    // 2) Fallback: schema sin attachments
    return await prisma.user.findUnique({
      where: { id: userId },
      include: AUTH_USER_INCLUDE,
    });
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
  if (!meUser.jewelryId) {
    return res.status(400).json({ message: "Jewelry not set for user." });
  }

  type MulterFile = { filename: string; originalname: string; mimetype: string; size: number };

  const files = (req as any).files as
    | {
        logo?: MulterFile[];
        attachments?: MulterFile[];
        "attachments[]"?: MulterFile[];
      }
    | undefined;

  const logoFile = files?.logo?.[0] ?? null;
  const attachments: MulterFile[] = [
    ...(files?.attachments ?? []),
    ...(files?.["attachments[]"] ?? []),
  ];

  const newLogoUrl = logoFile ? fileUrl(req, logoFile.filename) : undefined;

  const baseUpdateData: any = {
    name: s((data as any).name),
    phoneCountry: s((data as any).phoneCountry),
    phoneNumber: s((data as any).phoneNumber),
    street: s((data as any).street),
    number: s((data as any).number),
    city: s((data as any).city),
    province: s((data as any).province),
    postalCode: s((data as any).postalCode),
    country: s((data as any).country),
  };

  const extendedUpdateData: any = {
    ...baseUpdateData,
    legalName: s((data as any).legalName),
    cuit: s((data as any).cuit),
    ivaCondition: s((data as any).ivaCondition),
    email: s((data as any).email),
    website: s((data as any).website),
    notes: String((data as any).notes ?? ""),
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
        data: attachments.map((f: MulterFile) => ({
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
  if (!meUser.jewelryId) {
    return res.status(400).json({ message: "Jewelry not set for user." });
  }

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

  if (!attachmentId) {
    return res.status(400).json({ message: "ID inválido." });
  }

  const meUser = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!meUser) return res.status(404).json({ message: "User not found." });
  if (!meUser.jewelryId) {
    return res.status(400).json({ message: "Jewelry not set for user." });
  }

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
   - ✅ crea joyería + owner
   - ✅ permite reutilizar email en otras joyerías
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
      for (const module of ALL_MODULES) {
        for (const action of ALL_ACTIONS) {
          permissionsData.push({ module, action });
        }
      }

      await tx.permission.createMany({
        data: permissionsData,
        skipDuplicates: true,
      });

      const allPermissions: PermissionRow[] = await tx.permission.findMany();

      const permIdByKey = new Map<string, string>();
      for (const p of allPermissions) {
        permIdByKey.set(`${p.module}:${p.action}`, p.id);
      }

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
        include: AUTH_USER_INCLUDE,
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

    auditLog(req, {
      action: "auth.register",
      success: false,
      meta: { email, reason: "unknown_error" },
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
    auditLog(req, {
      action: "auth.login",
      success: false,
      meta: { email, reason: "missing_fields" },
    });
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  // 1) buscar cuántas joyerías tiene ese email (solo activos/no borrados)
  const tenants = await fetchUsersForLoginOptions(email);

  if (tenants.length === 0) {
    auditLog(req, {
      action: "auth.login",
      success: false,
      meta: { email, reason: "user_not_found" },
    });
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  // 2) si hay más de 1 joyería, tenantId obligatorio
  if (tenants.length > 1 && !tenantId) {
    auditLog(req, {
      action: "auth.login",
      success: false,
      meta: { email, reason: "tenant_required", tenantsCount: tenants.length },
    });
    return res.status(409).json({
      message: "Seleccioná la joyería para iniciar sesión.",
      code: "TENANT_REQUIRED",
      tenants,
    });
  }

  // 3) resolver tenantId final
  const finalTenantId = tenantId || tenants[0]?.id;

  const user = await fetchUserForAuthByEmailAndTenant(email, finalTenantId);

  if (!user) {
    auditLog(req, {
      action: "auth.login",
      success: false,
      meta: { email, reason: "user_not_found_in_tenant", tenantId: finalTenantId },
    });
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  if ((user as any).deletedAt) {
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

  auditLog(req, {
    action: "auth.logout",
    success: true,
    userId: (req as any).userId,
    tenantId: (req as any).tenantId,
  });

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
   PIN / QUICK SWITCH
========================= */
function isValidPin(pin: unknown) {
  const p = String(pin ?? "").trim();
  return /^\d{4}$/.test(p);
}

// ✅ lockout settings (simple, estable)
const PIN_MAX_FAILED = 5;
const PIN_LOCK_MINUTES = 5;

function lockUntilDate() {
  return new Date(Date.now() + PIN_LOCK_MINUTES * 60 * 1000);
}

function isLocked(lockedUntil: Date | null | undefined) {
  if (!lockedUntil) return false;
  return lockedUntil.getTime() > Date.now();
}

function lockPayload(lockedUntil: Date) {
  return {
    message: "PIN bloqueado. Intentá nuevamente más tarde.",
    code: "PIN_LOCKED",
    lockedUntil,
  };
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

async function recordPinFailure(args: {
  userId: string;
  tenantId: string;
  action: string;
  meta?: any;
}) {
  const u = await prisma.user.update({
    where: { id: args.userId },
    data: { quickPinFailedCount: { increment: 1 } },
    select: { quickPinFailedCount: true },
  });

  const failed = Number((u as any).quickPinFailedCount ?? 0);
  if (failed >= PIN_MAX_FAILED) {
    const lockedUntil = lockUntilDate();
    await prisma.user.update({
      where: { id: args.userId },
      data: {
        quickPinLockedUntil: lockedUntil,
        quickPinUpdatedAt: new Date(),
      },
    });

    auditLog({} as any, {
      action: args.action,
      success: false,
      userId: args.userId,
      tenantId: args.tenantId,
      meta: { ...(args.meta ?? {}), reason: "pin_locked", lockedUntil, failed },
    });

    return { locked: true as const, lockedUntil };
  }

  return { locked: false as const, failed };
}

async function clearPinFailures(userId: string) {
  await prisma.user.update({
    where: { id: userId },
    data: {
      quickPinFailedCount: 0,
      quickPinLockedUntil: null,
      quickPinUpdatedAt: new Date(),
    },
  });
}

/* ---------- SET PIN (crear / cambiar) ---------- */
export async function setMyPin(req: Request, res: Response) {
  const meUser = await requireActiveMe(req);
  if (!meUser) return res.status(401).json({ message: "Unauthorized" });

  const pin = String((req.body as any)?.pin ?? "").trim();
  if (!isValidPin(pin)) {
    return res.status(400).json({ message: "El PIN debe tener 4 dígitos." });
  }

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
  if (!isValidPin(pin)) {
    return res.status(400).json({ message: "PIN inválido." });
  }

  if (!meUser.quickPinEnabled || !meUser.quickPinHash) {
    return res.status(400).json({ message: "El PIN no está habilitado." });
  }

  if (isLocked(meUser.quickPinLockedUntil as any)) {
    return res.status(429).json(lockPayload(meUser.quickPinLockedUntil as any));
  }

  const ok = await bcrypt.compare(pin, String(meUser.quickPinHash));
  if (!ok) {
    const r = await recordPinFailure({
      userId: meUser.id,
      tenantId: meUser.jewelryId,
      action: "auth.pin_disable",
      meta: { reason: "invalid_pin" },
    });

    if (r.locked) return res.status(429).json(lockPayload(r.lockedUntil));

    auditLog(req, {
      action: "auth.pin_disable",
      success: false,
      userId: meUser.id,
      tenantId: meUser.jewelryId,
      meta: { reason: "invalid_pin", failed: r.failed },
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
  if (!isValidPin(pin)) {
    return res.status(400).json({ message: "PIN inválido." });
  }

  if (!meUser.quickPinEnabled || !meUser.quickPinHash) {
    return res.status(400).json({ message: "Este usuario no tiene PIN configurado." });
  }

  if (isLocked(meUser.quickPinLockedUntil as any)) {
    return res.status(429).json(lockPayload(meUser.quickPinLockedUntil as any));
  }

  const ok = await bcrypt.compare(pin, String(meUser.quickPinHash));
  if (!ok) {
    const r = await recordPinFailure({
      userId: meUser.id,
      tenantId: meUser.jewelryId,
      action: "auth.pin_unlock",
      meta: { reason: "invalid_pin" },
    });

    if (r.locked) return res.status(429).json(lockPayload(r.lockedUntil));

    auditLog(req, {
      action: "auth.pin_unlock",
      success: false,
      userId: meUser.id,
      tenantId: meUser.jewelryId,
      meta: { reason: "invalid_pin", failed: r.failed },
    });

    return res.status(401).json({ message: "PIN incorrecto." });
  }

  await clearPinFailures(meUser.id);

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
    },
    select: {
      id: true,
      email: true,
      name: true,
      avatarUrl: true,
      quickPinEnabled: true,
      quickPinHash: true,
      roles: {
        select: {
          roleId: true,
          role: { select: { name: true, isSystem: true } },
        },
      },
    },
    orderBy: { createdAt: "asc" },
  });

  return res.json({
    enabled: true,
    users: users.map((u: any) => {
      const roles = (u.roles ?? [])
        .map((ur: any) => ({
          id: ur.roleId,
          name: ur.role?.name,
          isSystem: ur.role?.isSystem ?? false,
        }))
        .filter((r: any) => typeof r?.name === "string" && r.name.trim());

      const roleNames = roles
        .map((r: any) => String(r.name).trim())
        .filter(Boolean);

      const roleLabel = roleNames.length ? roleNames.join(" • ") : "";

      const hasQuickPin = Boolean(u.quickPinEnabled && u.quickPinHash);
      const pinEnabled = Boolean(u.quickPinEnabled);

      return {
        id: u.id,
        email: u.email,
        name: u.name,
        avatarUrl: u.avatarUrl,

        // 🔐 PIN
        hasQuickPin,
        pinEnabled,
        hasPin: hasQuickPin,

        // ✅ ROLES (todas las variantes para frontend)
        roles,
        roleNames,
        roleLabel,
      };
    }),
  });
}

/* ---------- SWITCH USER ---------- */
export async function switchUserWithPin(req: Request, res: Response) {
  const meUser = await requireActiveMe(req);
  if (!meUser) return res.status(401).json({ message: "Unauthorized" });

  const j = await prisma.jewelry.findUnique({
    where: { id: meUser.jewelryId },
    select: { quickSwitchEnabled: true, pinLockRequireOnUserSwitch: true } as any,
  });

  const enabled = Boolean((j as any)?.quickSwitchEnabled);
  if (!enabled) {
    return res.status(403).json({ message: "Cambio rápido de usuario deshabilitado." });
  }

  const requireOnUserSwitch =
    typeof (j as any)?.pinLockRequireOnUserSwitch === "boolean"
      ? Boolean((j as any)?.pinLockRequireOnUserSwitch)
      : true;

  const targetUserId = String((req.body as any)?.targetUserId ?? "").trim();
  const pin = String((req.body as any)?.pin ?? "").trim(); // puede venir vacío si no se requiere

  if (!targetUserId) {
    return res.status(400).json({ message: "targetUserId requerido." });
  }

  if (requireOnUserSwitch && !isValidPin(pin)) {
    return res.status(400).json({ message: "PIN inválido." });
  }

  const target = await fetchUserForAuthById(targetUserId);

  if (!target || target.jewelryId !== meUser.jewelryId || (target as any).deletedAt) {
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

  if (requireOnUserSwitch) {
    if (!(target as any).quickPinEnabled || !(target as any).quickPinHash) {
      return res.status(400).json({ message: "El usuario seleccionado no tiene PIN configurado." });
    }

    const lockedUntil = (target as any).quickPinLockedUntil as Date | null | undefined;
    if (isLocked(lockedUntil)) {
      return res.status(429).json(lockPayload(lockedUntil as Date));
    }

    const ok = await bcrypt.compare(pin, String((target as any).quickPinHash));
    if (!ok) {
      const r = await recordPinFailure({
        userId: target.id,
        tenantId: target.jewelryId,
        action: "auth.pin_switch",
        meta: { reason: "invalid_pin", targetUserId, fromUserId: meUser.id },
      });

      if (r.locked) return res.status(429).json(lockPayload(r.lockedUntil));

      auditLog(req, {
        action: "auth.pin_switch",
        success: false,
        userId: meUser.id,
        tenantId: meUser.jewelryId,
        meta: { reason: "invalid_pin", targetUserId, failed: r.failed },
      });

      return res.status(401).json({ message: "PIN incorrecto." });
    }

    await clearPinFailures(target.id);
  }

  const token = signToken(target.id, target.jewelryId, target.tokenVersion);
  setAuthCookie(req, res, token);

  auditLog(req, {
    action: "auth.pin_switch",
    success: true,
    userId: target.id,
    tenantId: target.jewelryId,
    meta: {
      fromUserId: meUser.id,
      requireOnUserSwitch,
    },
  });

  return res.json(buildAuthResponse({ user: target, token, includeToken: true }));
}


/* =========================
   QUICK SWITCH (toggle por joyería)
========================= */
export async function setQuickSwitchForJewelry(req: Request, res: Response) {
  const userId = (req as any).userId as string | undefined;
  const tenantId = (req as any).tenantId as string | undefined;

  if (!userId) return res.status(401).json({ message: "Unauthorized" });
  if (!tenantId) return res.status(400).json({ message: "Tenant no definido." });

  const enabledRaw = (req.body as any)?.enabled ?? (req.body as any)?.quickSwitchEnabled;
  const enabled =
    enabledRaw === true || enabledRaw === "true" || enabledRaw === 1 || enabledRaw === "1";

  await prisma.jewelry.update({
    where: { id: tenantId },
    data: { quickSwitchEnabled: enabled } as any,
  });

  auditLog(req, {
    action: "company.security.quick_switch_set",
    success: true,
    userId,
    tenantId,
    meta: { enabled },
  });

  return res.json({ ok: true, enabled });
}

/* =========================
   PIN LOCK SETTINGS (joyería)
========================= */
export async function setPinLockSettingsForJewelry(req: Request, res: Response) {
  const userId = (req as any).userId as string | undefined;
  const tenantId = (req as any).tenantId as string | undefined;

  if (!userId) return res.status(401).json({ message: "Unauthorized" });
  if (!tenantId) return res.status(400).json({ message: "Tenant no definido." });

  const b = (req.body ?? {}) as any;

  const toBool = (v: any): boolean | undefined => {
    if (v === undefined || v === null) return undefined;
    if (typeof v === "boolean") return v;
    const s = String(v).trim().toLowerCase();
    if (s === "true" || s === "1") return true;
    if (s === "false" || s === "0") return false;
    return undefined;
  };

  const pinLockEnabled = toBool(b.pinLockEnabled);
  const pinLockRequireOnUserSwitch = toBool(b.pinLockRequireOnUserSwitch);
  const quickSwitchEnabled = toBool(b.quickSwitchEnabled);

  let pinLockTimeoutSec: number | undefined = undefined;
  if (b.pinLockTimeoutSec !== undefined && b.pinLockTimeoutSec !== null && b.pinLockTimeoutSec !== "") {
    const n = Number(b.pinLockTimeoutSec);
    if (!Number.isFinite(n)) {
      return res.status(400).json({ message: "pinLockTimeoutSec inválido." });
    }
    pinLockTimeoutSec = Math.max(10, Math.min(60 * 60 * 12, Math.trunc(n)));
  }

  const data: any = {};
  if (pinLockEnabled !== undefined) data.pinLockEnabled = pinLockEnabled;
  if (pinLockTimeoutSec !== undefined) data.pinLockTimeoutSec = pinLockTimeoutSec;
  if (pinLockRequireOnUserSwitch !== undefined) data.pinLockRequireOnUserSwitch = pinLockRequireOnUserSwitch;
  if (quickSwitchEnabled !== undefined) data.quickSwitchEnabled = quickSwitchEnabled;

  if (!Object.keys(data).length) {
    return res.status(400).json({ message: "No hay campos para actualizar." });
  }

  const updated = await prisma.jewelry.update({
    where: { id: tenantId },
    data: data as any,
    select: {
      pinLockEnabled: true,
      pinLockTimeoutSec: true,
      pinLockRequireOnUserSwitch: true,
      quickSwitchEnabled: true,
    } as any,
  });

  auditLog(req, {
    action: "company.security.pin_lock_set",
    success: true,
    userId,
    tenantId,
    meta: data,
  });

  return res.json({
    ok: true,
    pinLockEnabled: Boolean((updated as any).pinLockEnabled),
    pinLockTimeoutSec: Number((updated as any).pinLockTimeoutSec ?? 300),
    pinLockRequireOnUserSwitch: Boolean((updated as any).pinLockRequireOnUserSwitch),
    quickSwitchEnabled: Boolean((updated as any).quickSwitchEnabled),
  });
}

/* =========================
   LOGIN OPTIONS (email -> joyerías)
========================= */
export async function loginOptions(req: Request, res: Response) {
  const rawEmail = String((req.body as any)?.email ?? "").toLowerCase().trim();
  if (!rawEmail) return res.status(400).json({ message: "Email requerido." });

  const tenants = await fetchUsersForLoginOptions(rawEmail);

  return res.json({
    email: rawEmail,
    tenants,
  });
}
