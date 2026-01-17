// tptech-backend/src/modules/auth/auth.schemas.ts
import { z } from "zod";

/* =========================
   HELPERS
========================= */
const email = z.string().email();
const password = z.string().min(6);
const pin4 = z.string().regex(/^\d{4}$/, "El PIN debe tener 4 dígitos.");

/* =========================
   REGISTER
   (estricto, como decidimos)
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
   LOGIN / PASSWORD
========================= */
export const loginSchema = z.object({
  email,
  password: z.string().min(1),
});

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
/**
 * Reglas:
 * - name es el ÚNICO obligatorio
 * - el resto:
 *    - puede no venir
 *    - puede venir como string vacío ""
 * - compatible con JSON y multipart (parseJsonBodyField)
 */
export const updateJewelrySchema = z.object({
  // obligatorio
  name: z.string().min(1),

  // opcionales (aceptan "")
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

  // empresa
  logoUrl: z.string().optional(),
  legalName: z.string().optional(),
  cuit: z.string().optional(),
  ivaCondition: z.string().optional(),
  email: z.string().optional(),
  website: z.string().optional(),
  notes: z.string().optional(),
});

/* =========================
   ✅ PIN (SOLO DENTRO DEL SISTEMA)
   - nunca login externo
========================= */

// crear / cambiar PIN del usuario actual
export const pinSetSchema = z.object({
  pin: pin4,
});

// desactivar PIN (requiere PIN actual)
export const pinDisableSchema = z.object({
  pin: pin4,
});

// desbloquear pantalla (PIN del usuario actual)
export const pinUnlockSchema = z.object({
  pin: pin4,
});

// cambio rápido de usuario (si la joyería lo permite)
export const pinSwitchSchema = z.object({
  targetUserId: z.string().min(1),
  pin: pin4,
});
