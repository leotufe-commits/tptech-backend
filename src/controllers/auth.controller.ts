import type { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma.js";
import { sendResetEmail } from "../lib/mailer.js";
import { UserStatus } from "@prisma/client";

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error("❌ JWT_SECRET no está configurado");
const JWT_SECRET_SAFE: string = JWT_SECRET;

const APP_URL = process.env.APP_URL || "http://localhost:5174";

function signToken(userId: string) {
  return jwt.sign({ sub: userId }, JWT_SECRET_SAFE, { expiresIn: "7d" });
}

export async function me(req: Request, res: Response) {
  const userId = req.userId!;
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { jewelry: true },
  });

  if (!user) return res.status(404).json({ message: "User not found." });

  const safeUser: any = { ...user };
  delete safeUser.password;

  return res.json({ user: safeUser, jewelry: user.jewelry ?? null });
}

export async function updateMyJewelry(req: Request, res: Response) {
  const userId = req.userId!;
  const data = req.body as any;

  const me = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
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
      country: data.country.trim(),
    },
  });

  return res.json(updated);
}

export async function register(req: Request, res: Response) {
  const data = req.body as any;
  const email = String(data.email).toLowerCase().trim();

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
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

  const token = signToken(result.user.id);

  const safeUser: any = { ...result.user };
  delete safeUser.password;

  return res.status(201).json({
    user: safeUser,
    jewelry: result.jewelry,
    token,
  });
}

export async function login(req: Request, res: Response) {
  const data = req.body as any;
  const email = String(data.email).toLowerCase().trim();

  const user = await prisma.user.findUnique({
    where: { email },
    include: { jewelry: true },
  });

  if (!user) {
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  if (user.status !== UserStatus.ACTIVE) {
    return res.status(403).json({ message: "Usuario no habilitado." });
  }

  const ok = await bcrypt.compare(String(data.password), user.password);
  if (!ok) {
    return res.status(401).json({ message: "Email o contraseña incorrectos." });
  }

  const token = signToken(user.id);

  const safeUser: any = { ...user };
  delete safeUser.password;

  return res.json({
    user: safeUser,
    jewelry: user.jewelry ?? null,
    token,
  });
}

export async function forgotPassword(req: Request, res: Response) {
  const data = req.body as any;
  const email = String(data.email).toLowerCase().trim();

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.json({ ok: true });

  const resetToken = jwt.sign({ sub: user.id, type: "reset" }, JWT_SECRET_SAFE, {
    expiresIn: "30m",
  });

  const resetLink = `${APP_URL}/reset-password?token=${encodeURIComponent(resetToken)}`;
  await sendResetEmail(email, resetLink);

  return res.json({ ok: true });
}

export async function resetPassword(req: Request, res: Response) {
  const data = req.body as any;

  const payload = jwt.verify(String(data.token), JWT_SECRET_SAFE) as any;
  if (!payload?.sub || payload?.type !== "reset") {
    return res.status(401).json({ message: "Token inválido." });
  }

  const newHash = await bcrypt.hash(String(data.newPassword), 10);

  await prisma.user.update({
    where: { id: String(payload.sub) },
    data: { password: newHash },
  });

  return res.json({ ok: true });
}
