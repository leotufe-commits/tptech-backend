import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import { prisma } from "../lib/prisma.js";
import { sendResetEmail } from "../lib/mailer.js";
import { UserStatus } from "@prisma/client";
import { auditLog } from "../lib/auditLogger.js";
/* =========================
   ENV / CONST
========================= */
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET)
    throw new Error("❌ JWT_SECRET no está configurado");
const JWT_SECRET_SAFE = JWT_SECRET;
const APP_URL = process.env.APP_URL || "http://localhost:5174";
const JWT_ISSUER = process.env.JWT_ISSUER || "tptech";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "tptech-web";
// nombre único de cookie
const AUTH_COOKIE = "tptech_session";
/* =========================
   HELPERS
========================= */
function signToken(userId, tenantId) {
    return jwt.sign({ sub: userId, tenantId }, JWT_SECRET_SAFE, {
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
function setAuthCookie(_req, res, token) {
    const isProd = process.env.NODE_ENV === "production";
    res.cookie(AUTH_COOKIE, token, {
        httpOnly: true,
        secure: isProd, // ✅ solo true en prod
        sameSite: isProd ? "none" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
        path: "/",
    });
}
function clearAuthCookie(_req, res) {
    const isProd = process.env.NODE_ENV === "production";
    res.clearCookie(AUTH_COOKIE, {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? "none" : "lax",
        path: "/",
    });
}
/* =========================
   ME
========================= */
export async function me(req, res) {
    const userId = req.userId;
    if (!userId)
        return res.status(401).json({ message: "Unauthorized" });
    const user = await prisma.user.findUnique({
        where: { id: userId },
        include: { jewelry: true },
    });
    if (!user)
        return res.status(404).json({ message: "User not found." });
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
    const safeUser = { ...user };
    delete safeUser.password;
    return res.json({ user: safeUser, jewelry: user.jewelry ?? null });
}
/* =========================
   UPDATE JEWELRY
========================= */
export async function updateMyJewelry(req, res) {
    const userId = req.userId;
    const data = req.body;
    const meUser = await prisma.user.findUnique({
        where: { id: userId },
        select: { jewelryId: true },
    });
    if (!meUser)
        return res.status(404).json({ message: "User not found." });
    if (!meUser.jewelryId)
        return res.status(400).json({ message: "Jewelry not set for user." });
    const updated = await prisma.jewelry.update({
        where: { id: meUser.jewelryId },
        data: {
            name: data.name.trim(),
            firstName: data.firstName.trim(),
            lastName: data.lastName.trim(),
            phoneCountry: data.phoneCountry.trim(),
            phoneNumber: data.phoneNumber.trim(),
            street: data.street.trim(),
            number: data.number.trim(),
            city: data.city.trim(),
            province: data.province.trim(),
            postalCode: data.postalCode.trim(),
            country: data.country.trim(),
        },
    });
    auditLog(req, {
        action: "jewelry.update_profile",
        success: true,
        userId,
        tenantId: meUser.jewelryId,
    });
    return res.json(updated);
}
/* =========================
   REGISTER
========================= */
export async function register(req, res) {
    const data = req.body;
    const email = String(data.email).toLowerCase().trim();
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
        auditLog(req, {
            action: "auth.register",
            success: false,
            meta: { email, reason: "email_already_registered" },
        });
        return res.status(409).json({ message: "El email ya está registrado." });
    }
    const hashed = await bcrypt.hash(String(data.password), 10);
    const result = await prisma.$transaction(async (tx) => {
        const jewelry = await tx.jewelry.create({
            data: {
                name: data.jewelryName.trim(),
                firstName: data.firstName.trim(),
                lastName: data.lastName.trim(),
                phoneCountry: data.phoneCountry.trim(),
                phoneNumber: data.phoneNumber.trim(),
                street: data.street.trim(),
                number: data.number.trim(),
                city: data.city.trim(),
                province: data.province.trim(),
                postalCode: data.postalCode.trim(),
                country: data.country.trim(),
            },
        });
        const user = await tx.user.create({
            data: {
                email,
                password: hashed,
                name: `${data.firstName.trim()} ${data.lastName.trim()}`.trim(),
                status: UserStatus.ACTIVE,
                jewelryId: jewelry.id,
            },
            include: { jewelry: true },
        });
        return { user, jewelry };
    });
    const token = signToken(result.user.id, result.user.jewelryId);
    // ✅ cookie (httpOnly)
    setAuthCookie(req, res, token);
    auditLog(req, {
        action: "auth.register",
        success: true,
        userId: result.user.id,
        tenantId: result.user.jewelryId,
        meta: { email },
    });
    const safeUser = { ...result.user };
    delete safeUser.password;
    return res.status(201).json({
        user: safeUser,
        jewelry: result.jewelry,
        token, // ✅ devolver token también
    });
}
/* =========================
   LOGIN
========================= */
export async function login(req, res) {
    const data = req.body;
    const email = String(data.email).toLowerCase().trim();
    const password = String(data.password || "");
    const user = await prisma.user.findUnique({
        where: { email },
        include: { jewelry: true },
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
    const token = signToken(user.id, user.jewelryId);
    // ✅ cookie (httpOnly)
    setAuthCookie(req, res, token);
    auditLog(req, {
        action: "auth.login",
        success: true,
        userId: user.id,
        tenantId: user.jewelryId,
    });
    const safeUser = { ...user };
    delete safeUser.password;
    return res.json({
        user: safeUser,
        jewelry: user.jewelry ?? null,
        token, // ✅ devolver token también
    });
}
/* =========================
   LOGOUT
========================= */
export async function logout(req, res) {
    clearAuthCookie(req, res);
    auditLog(req, {
        action: "auth.logout",
        success: true,
        userId: req.userId,
        tenantId: req.tenantId,
    });
    // ✅ estándar + compatible con apiFetch (maneja 204)
    return res.status(204).send();
}
/* =========================
   FORGOT PASSWORD
========================= */
export async function forgotPassword(req, res) {
    const data = req.body;
    const email = String(data.email).toLowerCase().trim();
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
export async function resetPassword(req, res) {
    const data = req.body;
    try {
        const payload = jwt.verify(String(data.token), JWT_SECRET_SAFE, {
            issuer: JWT_ISSUER,
            audience: JWT_AUDIENCE,
        });
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
        const newHash = await bcrypt.hash(String(data.newPassword), 10);
        await prisma.user.update({
            where: { id: userId },
            data: { password: newHash },
        });
        auditLog(req, {
            action: "auth.reset_password",
            success: true,
            userId: user.id,
            tenantId: user.jewelryId,
            meta: { jti: String(payload.jti) },
        });
        return res.json({ ok: true });
    }
    catch {
        auditLog(req, {
            action: "auth.reset_password",
            success: false,
            meta: { reason: "jwt_verify_failed" },
        });
        return res.status(401).json({ message: "Token inválido." });
    }
}
//# sourceMappingURL=auth.controller.js.map