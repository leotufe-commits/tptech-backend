import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma.js";
import { setContextTenantId, setContextUserId } from "../lib/prisma.js";
import { OverrideEffect } from "@prisma/client";
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET)
    throw new Error("❌ JWT_SECRET no está configurado");
const JWT_SECRET_SAFE = JWT_SECRET;
const JWT_ISSUER = process.env.JWT_ISSUER || "tptech";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "tptech-web";
// mismo nombre que en auth.controller.ts
const AUTH_COOKIE = "tptech_session";
function getTokenFromReq(req) {
    // 1) Authorization: Bearer <token>
    const h = req.headers.authorization;
    if (h && typeof h === "string") {
        const m = h.match(/^Bearer\s+(.+)$/i);
        if (m?.[1])
            return m[1].trim();
    }
    // 2) Cookie (prod)
    const c = req.cookies?.[AUTH_COOKIE];
    if (typeof c === "string" && c.trim())
        return c.trim();
    return null;
}
export async function requireAuth(req, res, next) {
    const token = getTokenFromReq(req);
    if (!token) {
        return res.status(401).json({ message: "Unauthorized" });
    }
    try {
        const payload = jwt.verify(token, JWT_SECRET_SAFE, {
            issuer: JWT_ISSUER,
            audience: JWT_AUDIENCE,
        });
        const userId = String(payload?.sub || "");
        const tenantId = String(payload?.tenantId || "");
        const tokenVersion = Number(payload?.tokenVersion ?? 0);
        if (!userId || !tenantId) {
            return res.status(401).json({ message: "Unauthorized" });
        }
        // Validación “extra” (opcional pero recomendada): tokenVersion
        const user = await prisma.user.findFirst({
            where: { id: userId, jewelryId: tenantId },
            select: { id: true, jewelryId: true, tokenVersion: true, status: true },
        });
        if (!user)
            return res.status(401).json({ message: "Unauthorized" });
        if (user.tokenVersion !== tokenVersion) {
            return res.status(401).json({ message: "Sesión expirada" });
        }
        // set req (tipado ya viene por express.d.ts)
        req.userId = user.id;
        req.tenantId = user.jewelryId;
        // ALS (multi-tenant)
        setContextUserId(user.id);
        setContextTenantId(user.jewelryId);
        // permissions para requirePermission
        const full = await prisma.user.findFirst({
            where: { id: user.id, jewelryId: user.jewelryId },
            select: {
                roles: {
                    select: {
                        role: {
                            select: {
                                permissions: {
                                    select: { permission: { select: { module: true, action: true } } },
                                },
                            },
                        },
                    },
                },
                permissionOverrides: {
                    select: { effect: true, permission: { select: { module: true, action: true } } },
                },
            },
        });
        const perms = [];
        // roles
        for (const ur of full?.roles ?? []) {
            for (const rp of ur.role?.permissions ?? []) {
                perms.push(`${rp.permission.module}:${rp.permission.action}`);
            }
        }
        // overrides
        const allow = new Set();
        const deny = new Set();
        for (const ov of full?.permissionOverrides ?? []) {
            const key = `${ov.permission.module}:${ov.permission.action}`;
            if (ov.effect === OverrideEffect.ALLOW)
                allow.add(key);
            if (ov.effect === OverrideEffect.DENY)
                deny.add(key);
        }
        const base = new Set(perms);
        for (const d of deny)
            base.delete(d);
        for (const a of allow)
            base.add(a);
        for (const d of deny)
            base.delete(d);
        req.permissions = Array.from(base);
        return next();
    }
    catch {
        return res.status(401).json({ message: "Unauthorized" });
    }
}
//# sourceMappingURL=requireAuth.js.map