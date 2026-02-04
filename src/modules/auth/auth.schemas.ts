// tptech-backend/src/modules/auth/auth.schemas.ts
import { z } from "zod";

/* =========================
   HELPERS
========================= */
const email = z.string().email("Email inválido.");
const password = z.string().min(6, "La contraseña debe tener al menos 6 caracteres.");
const pin4 = z.string().regex(/^\d{4}$/, "El PIN debe tener 4 dígitos.");

/* =========================
   REGISTER
========================= */
export const registerSchema = z.object({
  email,
  password,

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

/* =========================
   LOGIN
========================= */
export const loginSchema = z.object({
  tenantId: z.string().min(1, "Tenant requerido."),
  email,
  password: z.string().min(1, "Contraseña requerida."),
});

/* ✅ Opciones de login por email (joyerías asociadas) */
export const loginOptionsSchema = z.object({
  email,
});

/* =========================
   PASSWORD
========================= */
export const forgotSchema = z.object({
  email,
});

export const resetSchema = z.object({
  token: z.string().min(10),
  newPassword: password,
});

/* =========================
   UPDATE EMPRESA / JOYERÍA
========================= */
export const updateJewelrySchema = z.object({
  name: z.string().min(1),

  firstName: z.string().optional(),
  lastName: z.string().optional(),

  phoneCountry: z.string().optional(),
  phoneNumber: z.string().optional(),

  street: z.string().optional(),
  number: z.string().optional(),
  city: z.string().optional(),
  province: z.string().optional(),
  postalCode: z.string().optional(),
  country: z.string().optional(),

  logoUrl: z.string().optional(),
  legalName: z.string().optional(),
  cuit: z.string().optional(),
  ivaCondition: z.string().optional(),
  email: z.string().optional(),
  website: z.string().optional(),
  notes: z.string().optional(),
});

/* =========================
   🔐 PIN (SOLO DENTRO DEL SISTEMA)
========================= */
export const pinSetSchema = z.object({
  pin: pin4,
});

export const pinDisableSchema = z.object({
  pin: pin4,
});

export const pinUnlockSchema = z.object({
  pin: pin4,
});

/* ✅ PIN opcional para permitir switch sin PIN
   cuando la joyería lo habilita */
export const pinSwitchSchema = z.object({
  targetUserId: z.string().min(1),
  pin: pin4.optional(),
});

/* =========================
   🔐 CONFIG PIN / LOCK (JOYERÍA)
========================= */
export const pinLockSettingsSchema = z.object({
  pinLockEnabled: z.boolean(),
  pinLockTimeoutSec: z.number().int().min(30).max(60 * 60 * 12),
  pinLockRequireOnUserSwitch: z.boolean(),
  quickSwitchEnabled: z.boolean(),
});
