import { Router } from "express";
import type { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { UserStatus } from "@prisma/client";
import { prisma } from "../lib/prisma.js";
import { sendResetEmail } from "../lib/mailer.js";
import { requireAuth } from "../middlewares/requireAuth.js";

const router = Router();

/* ===========================
   ENV
=========================== */

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("❌ JWT_SECRET no está configurado");
}
const JWT_SECRET_SAFE: string = JWT_SECRET;

const APP_URL = process.env.APP_URL || "http://localhost:5174";

/* ===========================
   HELPERS
=========================== */

function signToken(userId: string) {
  return jwt.sign({ sub: userId }, JWT_SECRET_SAFE, { expiresIn: "7d" });
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
  country: z.string().min(1)
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});

const forgotSchema = z.object({
  email: z.string().email()
});

const resetSchema = z.object({
  token: z.string().min(10),
  newPassword: z.string().min(6)
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
  country: z.string().min(1)
});

/* ===========================
   ROUTES
=========================== */

/** GET /auth/me */
router.get("/me", requireAuth, async (req, res) => {
  const userId = req.userId!;
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { jewelry: true }
  });

  if (!user) return res.status(404).json({ message: "User not found." });

  const safeUser: any = { ...user };
  delete safeUser.password;

  return res.json({
    user: safeUser,
    jewelry: user.jewelry ?? null
  });
});

/** PUT /auth/me/jewelry */
router.put("/me/jewelry", requireAuth, async (req, res) => {
  try {
    const userId = req.userId!;
    const data = updateJewelrySchema.parse(req.body);

    const me = await prisma.user.findUnique({
      where: { id: userId },
      select: { jewelryId: true }
    });

    if (!me) return res.status(404).json({ message: "User not found." });

    const updated = await prisma.jewelry.update({
      where: { id: me.jewelryId },
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
        country: data.country.trim()
      }
    });

    return res.json(updated);
  } catch (err: any) {
    if (err?.name === "ZodError") {
      return res.status(400).json({ message: "Datos inválidos.", issues: err.issues });
    }
    console.error(err);
    return res.status(500).json({ message: "Error interno." });
  }
});

/** POST /auth/register */
router.post("/register", async (req, res) => {
  const data = registerSchema.parse(req.body);
  const email = data.email.toLowerCase().trim();

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return res.status(409).json({ message: "El email ya está registrado." });
  }

  const hashed = await bcrypt.hash(data.password, 10);

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
        country: data.country.trim()
      }
    });

    const user = await tx.user.create({
      data: {
        email,
        password: hashed,
        name: `${data.firstName.trim()} ${data.lastName.trim()}`.trim(),
        status: UserStatus.ACTIVE,
        jewelryId: jewelry.id
      },
      include: { jewelry: true }
    });

    return { user, jewelry };
  });

  const token = signToken(result.user.id);

  const safeUser: any = { ...result.user };
  delete safeUser.password;

  return res.status(201).json({
    user: safeUser,
    jewelry: result.jewelry,
    token
  });
});

/** POST /auth/login */
router.post("/login", async (req, res) => {
  const data = loginSchema.parse(req.body);
  const email = data.email.toLowerCase().trim();

  const user = await prisma.user.findUnique({
    where: { email },
    include: { jewelry: true }
  });

  if (!user) {
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  const ok = await bcrypt.compare(data.password, user.password);
  if (!ok) {
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  const token = signToken(user.id);

  const safeUser: any = { ...user };
  delete safeUser.password;

  return res.json({
    user: safeUser,
    jewelry: user.jewelry ?? null,
    token
  });
});

/** POST /auth/forgot-password */
router.post("/forgot-password", async (req, res) => {
  const data = forgotSchema.parse(req.body);
  const email = data.email.toLowerCase().trim();

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.json({ ok: true });

  const resetToken = jwt.sign(
    { sub: user.id, type: "reset" },
    JWT_SECRET_SAFE,
    { expiresIn: "30m" }
  );

  const resetLink = `${APP_URL}/reset-password?token=${encodeURIComponent(resetToken)}`;
  await sendResetEmail(email, resetLink);

  return res.json({ ok: true });
});

/** POST /auth/reset-password */
router.post("/reset-password", async (req, res) => {
  const data = resetSchema.parse(req.body);

  const payload = jwt.verify(data.token, JWT_SECRET_SAFE) as any;
  if (!payload?.sub || payload?.type !== "reset") {
    return res.status(401).json({ message: "Token inválido." });
  }

  const newHash = await bcrypt.hash(data.newPassword, 10);

  await prisma.user.update({
    where: { id: String(payload.sub) },
    data: { password: newHash }
  });

  return res.json({ ok: true });
});

export default router;
