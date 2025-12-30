import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { sendResetEmail } from "../lib/mailer.js";
import { requireAuth } from "../middlewares/requireAuth.js";

const router = Router();

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const APP_URL = process.env.APP_URL || "http://localhost:5174"; // Front

function signToken(userId: string) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: "7d" });
}

/* ===========================
   SCHEMAS
=========================== */

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),

  jewelryName: z.string().min(1),
  firstName: z.string().min(1),
  lastName: z.string().min(1),

  phoneCountry: z.string().min(1),
  phoneNumber: z.string().min(1),

  street: z.string().min(1),
  number: z.string().min(1),
  city: z.string().min(1),
  province: z.string().min(1),
  postalCode: z.string().min(1),
  country: z.string().min(1),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const forgotSchema = z.object({
  email: z.string().email(),
});

const resetSchema = z.object({
  token: z.string().min(10),
  newPassword: z.string().min(6),
});

const updateJewelrySchema = z.object({
  name: z.string().min(1),

  firstName: z.string().min(1),
  lastName: z.string().min(1),

  phoneCountry: z.string().min(1),
  phoneNumber: z.string().min(1),

  street: z.string().min(1),
  number: z.string().min(1),
  city: z.string().min(1),
  province: z.string().min(1),
  postalCode: z.string().min(1),
  country: z.string().min(1),
});

/* ===========================
   ROUTES
=========================== */

/** GET /auth/me */
router.get("/me", requireAuth, async (req, res) => {
  try {
    const userId = req.userId!;
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { jewelry: true },
    });

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    const { password, ...safeUser } = user;

    return res.json({
      user: safeUser,
      jewelry: user.jewelry ?? null,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Error interno." });
  }
});

/** PUT /auth/me/jewelry */
router.put("/me/jewelry", requireAuth, async (req, res) => {
  try {
    const userId = req.userId!;
    const data = updateJewelrySchema.parse(req.body);

    const updated = await prisma.jewelry.update({
      where: { userId },
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

    return res.json(updated);
  } catch (err: any) {
    if (err?.name === "ZodError") {
      return res.status(400).json({ message: "Datos inválidos.", issues: err.issues });
    }
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

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res.status(409).json({ message: "El email ya está registrado." });
    }

    const hashed = await bcrypt.hash(data.password, 10);

    const result = await prisma.$transaction(async (tx: any) => {
      const user = await tx.user.create({
        data: {
          email,
          password: hashed,
          name: `${data.firstName} ${data.lastName}`.trim(),
        },
      });

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
          userId: user.id,
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
  } catch (err: any) {
    if (err?.name === "ZodError") {
      return res.status(400).json({ message: "Datos inválidos.", issues: err.issues });
    }
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

    const user = await prisma.user.findUnique({
      where: { email },
      include: { jewelry: true },
    });

    if (!user) {
      return res.status(401).json({ message: "Email o contraseña incorrectos." });
    }

    const ok = await bcrypt.compare(data.password, user.password);
    if (!ok) {
      return res.status(401).json({ message: "Email o contraseña incorrectos." });
    }

    const token = signToken(user.id);

    return res.json({
      user: { id: user.id, email: user.email, name: user.name },
      jewelry: user.jewelry ?? null,
      token,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Error interno." });
  }
});

/** POST /auth/forgot-password */
router.post("/forgot-password", async (req, res) => {
  try {
    const data = forgotSchema.parse(req.body);
    const email = data.email.toLowerCase().trim();

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.json({ ok: true });

    const resetToken = jwt.sign(
      { sub: user.id, type: "reset" },
      JWT_SECRET,
      { expiresIn: "30m" }
    );

    const resetLink = `${APP_URL}/reset-password?token=${encodeURIComponent(resetToken)}`;
    await sendResetEmail(email, resetLink);

    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Error interno." });
  }
});

/** POST /auth/reset-password */
router.post("/reset-password", async (req, res) => {
  try {
    const data = resetSchema.parse(req.body);

    const payload: any = jwt.verify(data.token, JWT_SECRET);
    if (!payload?.sub || payload?.type !== "reset") {
      return res.status(401).json({ message: "Token inválido." });
    }

    const hashed = await bcrypt.hash(data.newPassword, 10);

    await prisma.user.update({
      where: { id: String(payload.sub) },
      data: { password: hashed },
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Error interno." });
  }
});

export default router;
