import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { sendResetEmail } from "../lib/mailer.js";
import { requireAuth } from "../middlewares/requireAuth.js";

const router = Router();

/**
 * ✅ PRODUCCIÓN: no permitir fallback inseguro
 * Si JWT_SECRET no existe, el server debe fallar al iniciar.
 */
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET no está configurado");
}

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

    // compat: si tu tabla todavía tiene "password" (viejo) lo sacamos
    // y si ya migraste a "passwordHash" también lo sacamos
    // (no rompe aunque no exista)
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, passwordHash, ...safeUser } = user as any;

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

    // Nota: en tu schema actual "Jewelry" parece no tener userId,
    // pero si lo tiene en la DB legacy, esto funciona.
    // Si ya migraste al nuevo modelo (jewelryId en User),
    // lo ajustamos en el siguiente paso.
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
      return res
        .status(400)
        .json({ message: "Datos inválidos.", issues: err.issues });
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

    // Guardamos hash, NUNCA plaintext
    const passwordHash = await bcrypt.hash(data.password, 10);

    const result = await prisma.$transaction(async (tx: any) => {
      const user = await tx.user.create({
        data: {
          email,
          // compat: si tu modelo usa passwordHash, guardamos ahí
          // si usa password (legacy), Prisma tirará error y lo vemos al toque.
          passwordHash,
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
          userId: user.id, // legacy
        },
      });

      return { user, jewelry };
    });

    const token = signToken(result.user.id);

    // Nunca devolver hashes
    const { password, passwordHash: _ph, ...safeUser } = result.user as any;

    return res.status(201).json({
      user: safeUser,
      jewelry: result.jewelry,
      token,
    });
  } catch (err: any) {
    if (err?.name === "ZodError") {
      return res
        .status(400)
        .json({ message: "Datos inválidos.", issues: err.issues });
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

    // compat: soportar DB legacy (password) y nuevo (passwordHash)
    const hash = (user as any).passwordHash ?? (user as any).password ?? null;
    if (!hash) {
      return res.status(401).json({ message: "Email o contraseña incorrectos." });
    }

    const ok = await bcrypt.compare(data.password, hash);
    if (!ok) {
      return res.status(401).json({ message: "Email o contraseña incorrectos." });
    }

    const token = signToken(user.id);

    return res.json({
      user: { id: user.id, email: user.email, name: (user as any).name ?? null },
      jewelry: user.jewelry ?? null,
      token,
    });
  } catch (err) {
    console.error("🔥 LOGIN ERROR:", err);
    return res.status(500).json({
      message: "Error interno login",
      error: String(err),
    });
  }
});

/** POST /auth/forgot-password */
router.post("/forgot-password", async (req, res) => {
  try {
    const data = forgotSchema.parse(req.body);
    const email = data.email.toLowerCase().trim();

    const user = await prisma.user.findUnique({ where: { email } });

    // ✅ anti-enumeración: siempre responder ok
    if (!user) return res.json({ ok: true });

    const resetToken = jwt.sign({ sub: user.id, type: "reset" }, JWT_SECRET, {
      expiresIn: "30m",
    });

    const resetLink = `${APP_URL}/reset-password?token=${encodeURIComponent(
      resetToken
    )}`;

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

    const newHash = await bcrypt.hash(data.newPassword, 10);

    await prisma.user.update({
      where: { id: String(payload.sub) },
      data: {
        // compat: preferimos passwordHash
        passwordHash: newHash,
      } as any,
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Error interno." });
  }
});

export default router;
