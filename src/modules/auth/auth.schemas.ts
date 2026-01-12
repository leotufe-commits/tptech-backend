// src/modules/auth/auth.schemas.ts
import { z } from "zod";

export const registerSchema = z.object({
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

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

export const forgotSchema = z.object({
  email: z.string().email(),
});

export const resetSchema = z.object({
  token: z.string().min(10),
  newPassword: z.string().min(6),
});

/**
 * ✅ UPDATE empresa/joyería
 * - name requerido (Nombre de fantasía)
 * - el resto es opcional y permite ""
 * - agrega campos nuevos de empresa
 *
 * Importante: permite tanto JSON como multipart parseado (parseJsonBodyField("data"))
 */
export const updateJewelrySchema = z.object({
  // requerido
  name: z.string().min(1),

  // opcionales (permiten string vacío)
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

  // ✅ nuevos campos empresa
  logoUrl: z.string().optional(),
  legalName: z.string().optional(),
  cuit: z.string().optional(),
  ivaCondition: z.string().optional(),
  email: z.string().optional(),
  website: z.string().optional(),
  notes: z.string().optional(),
});
