"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const zod_1 = require("zod");
const prisma_1 = require("../lib/prisma");
const mailer_1 = require("../lib/mailer");
const requireAuth_1 = require("../middlewares/requireAuth");
const router = (0, express_1.Router)();
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const APP_URL = process.env.APP_URL || "http://localhost:5174"; // Front
function signToken(userId) {
    return jsonwebtoken_1.default.sign({ sub: userId }, JWT_SECRET, { expiresIn: "7d" });
}
/**
 * Register: crea User + Jewelry (1-1)
 * El frontend manda:
 *  - email, password
 *  - jewelryName, firstName, lastName, phoneCountry, phoneNumber
 *  - street, number, city, province, postalCode, country
 */
const registerSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string().min(6),
    jewelryName: zod_1.z.string().min(1),
    firstName: zod_1.z.string().min(1),
    lastName: zod_1.z.string().min(1),
    phoneCountry: zod_1.z.string().min(1),
    phoneNumber: zod_1.z.string().min(1),
    street: zod_1.z.string().min(1),
    number: zod_1.z.string().min(1),
    city: zod_1.z.string().min(1),
    province: zod_1.z.string().min(1),
    postalCode: zod_1.z.string().min(1),
    country: zod_1.z.string().min(1),
});
const loginSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string().min(1),
});
const forgotSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
});
const resetSchema = zod_1.z.object({
    token: zod_1.z.string().min(10),
    newPassword: zod_1.z.string().min(6),
});
const updateJewelrySchema = zod_1.z.object({
    name: zod_1.z.string().min(1),
    firstName: zod_1.z.string().min(1),
    lastName: zod_1.z.string().min(1),
    phoneCountry: zod_1.z.string().min(1),
    phoneNumber: zod_1.z.string().min(1),
    street: zod_1.z.string().min(1),
    number: zod_1.z.string().min(1),
    city: zod_1.z.string().min(1),
    province: zod_1.z.string().min(1),
    postalCode: zod_1.z.string().min(1),
    country: zod_1.z.string().min(1),
});
/** GET /auth/me (usuario + joyería logueada) */
router.get("/me", requireAuth_1.requireAuth, async (req, res) => {
    try {
        const userId = req.userId;
        const user = await prisma_1.prisma.user.findUnique({
            where: { id: userId },
            include: { jewelry: true },
        });
        if (!user)
            return res.status(404).json({ message: "User not found." });
        const { password, ...safeUser } = user;
        return res.json({
            user: safeUser,
            jewelry: user.jewelry ?? null,
        });
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Error interno." });
    }
});
/** PUT /auth/me/jewelry (actualiza la joyería del usuario logueado) */
router.put("/me/jewelry", requireAuth_1.requireAuth, async (req, res) => {
    try {
        const userId = req.userId;
        const data = updateJewelrySchema.parse(req.body);
        const updated = await prisma_1.prisma.jewelry.update({
            where: { userId }, // Jewelry.userId es unique
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
                userId: true,
                createdAt: true,
                updatedAt: true,
            },
        });
        return res.json(updated);
    }
    catch (err) {
        if (err?.name === "ZodError") {
            return res.status(400).json({ message: "Datos inválidos.", issues: err.issues });
        }
        // Prisma: Record to update not found
        if (err?.code === "P2025") {
            return res.status(404).json({ message: "Joyería no encontrada." });
        }
        console.error(err);
        return res.status(500).json({ message: "Error interno." });
    }
});
/** POST /auth/register */
router.post("/register", async (req, res) => {
    try {
        const data = registerSchema.parse(req.body);
        const email = data.email.toLowerCase().trim();
        // Normalizamos strings
        const jewelryName = data.jewelryName.trim();
        const firstName = data.firstName.trim();
        const lastName = data.lastName.trim();
        const phoneCountry = data.phoneCountry.trim();
        const phoneNumber = data.phoneNumber.trim();
        const street = data.street.trim();
        const number = data.number.trim();
        const city = data.city.trim();
        const province = data.province.trim();
        const postalCode = data.postalCode.trim();
        const country = data.country.trim();
        const existing = await prisma_1.prisma.user.findUnique({ where: { email } });
        if (existing) {
            return res.status(409).json({ message: "El email ya está registrado." });
        }
        const hashed = await bcryptjs_1.default.hash(data.password, 10);
        // Crear User + Jewelry en una transacción
        const result = await prisma_1.prisma.$transaction(async (tx) => {
            const user = await tx.user.create({
                data: {
                    email,
                    password: hashed,
                    name: `${firstName} ${lastName}`.trim(),
                },
                select: { id: true, email: true, name: true, createdAt: true },
            });
            const jewelry = await tx.jewelry.create({
                data: {
                    name: jewelryName,
                    firstName,
                    lastName,
                    phoneCountry,
                    phoneNumber,
                    street,
                    number,
                    city,
                    province,
                    postalCode,
                    country,
                    userId: user.id,
                },
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
                    userId: true,
                    createdAt: true,
                },
            });
            return { user, jewelry };
        });
        const token = signToken(result.user.id);
        return res.status(201).json({
            user: result.user,
            jewelry: result.jewelry,
            token,
        });
    }
    catch (err) {
        // Zod
        if (err?.name === "ZodError") {
            return res.status(400).json({ message: "Datos inválidos.", issues: err.issues });
        }
        // Prisma unique error (por carrera)
        if (err?.code === "P2002") {
            return res.status(409).json({ message: "El email ya está registrado." });
        }
        console.error(err);
        return res.status(500).json({ message: "Error interno." });
    }
});
/** POST /auth/login */
router.post("/login", async (req, res) => {
    try {
        const data = loginSchema.parse(req.body);
        const email = data.email.toLowerCase().trim();
        const user = await prisma_1.prisma.user.findUnique({
            where: { email },
            include: { jewelry: true },
        });
        if (!user)
            return res.status(401).json({ message: "Email o contraseña incorrectos." });
        const ok = await bcryptjs_1.default.compare(data.password, user.password);
        if (!ok)
            return res.status(401).json({ message: "Email o contraseña incorrectos." });
        const token = signToken(user.id);
        return res.json({
            user: { id: user.id, email: user.email, name: user.name, createdAt: user.createdAt },
            jewelry: user.jewelry ?? null,
            token,
        });
    }
    catch (err) {
        if (err?.name === "ZodError") {
            return res.status(400).json({ message: "Datos inválidos.", issues: err.issues });
        }
        console.error(err);
        return res.status(500).json({ message: "Error interno." });
    }
});
/** POST /auth/forgot-password
 *  Siempre responde ok:true (no revela si el email existe)
 */
router.post("/forgot-password", async (req, res) => {
    try {
        const data = forgotSchema.parse(req.body);
        const email = data.email.toLowerCase().trim();
        const user = await prisma_1.prisma.user.findUnique({ where: { email } });
        // Por seguridad: no revelar si existe o no
        if (!user)
            return res.json({ ok: true });
        // Token de reset (30 min)
        const resetToken = jsonwebtoken_1.default.sign({ sub: user.id, type: "reset" }, JWT_SECRET, {
            expiresIn: "30m",
        });
        const resetLink = `${APP_URL}/reset-password?token=${encodeURIComponent(resetToken)}`;
        await (0, mailer_1.sendResetEmail)(email, resetLink);
        return res.json({ ok: true });
    }
    catch (err) {
        if (err?.name === "ZodError") {
            return res.status(400).json({ message: "Datos inválidos.", issues: err.issues });
        }
        console.error(err);
        return res.status(500).json({ message: "Error interno." });
    }
});
/** POST /auth/reset-password */
router.post("/reset-password", async (req, res) => {
    try {
        const data = resetSchema.parse(req.body);
        let payload;
        try {
            payload = jsonwebtoken_1.default.verify(data.token, JWT_SECRET);
        }
        catch {
            return res.status(401).json({ message: "Token inválido o expirado." });
        }
        if (!payload?.sub || payload?.type !== "reset") {
            return res.status(401).json({ message: "Token inválido." });
        }
        const userId = String(payload.sub);
        const hashed = await bcryptjs_1.default.hash(data.newPassword, 10);
        await prisma_1.prisma.user.update({
            where: { id: userId },
            data: { password: hashed },
        });
        return res.json({ ok: true });
    }
    catch (err) {
        if (err?.name === "ZodError") {
            return res.status(400).json({ message: "Datos inválidos.", issues: err.issues });
        }
        console.error(err);
        return res.status(500).json({ message: "Error interno." });
    }
});
exports.default = router;
