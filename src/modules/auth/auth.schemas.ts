// tptech-backend/src/modules/auth/auth.schemas.ts
import { z } from "zod";

/* =========================
   HELPERS
========================= */
const email = z.string().email("Email inválido.");
const password = z.string().min(6, "La contraseña debe tener al menos 6 caracteres.");

// PIN como string "1234"
const pin4 = z.string().regex(/^\d{4}$/, "El PIN debe tener 4 dígitos.");

/** Acepta pin en variantes y lo normaliza a string */
const pinInput = z.union([z.string(), z.number()]).transform((v) => String(v ?? "").trim());

/** Acepta boolean en varias formas (true/"true"/1/"1") */
const boolInput = z
  .union([z.boolean(), z.string(), z.number()])
  .transform((v) => {
    if (typeof v === "boolean") return v;
    const s = String(v ?? "").trim().toLowerCase();
    if (s === "true" || s === "1") return true;
    if (s === "false" || s === "0") return false;
    // si viene cualquier cosa rara, dejamos undefined para que Zod falle si era requerido
    return undefined as unknown as boolean;
  });

/** Acepta número en varias formas */
const numInput = z.union([z.number(), z.string()]).transform((v) => {
  const n = typeof v === "number" ? v : Number(String(v ?? "").trim());
  return n;
});

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
  // ✅ tenantId es opcional: el controller ya resuelve si hay 1 sola joyería
  tenantId: z.string().min(1, "Tenant requerido.").optional(),
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
   ✅ Compat: pin | pin4
========================= */
export const pinSetSchema = z
  .object({
    pin: pinInput.optional(),
    pin4: pinInput.optional(),
  })
  .superRefine((v, ctx) => {
    const p = String(v.pin ?? v.pin4 ?? "").trim();
    if (!/^\d{4}$/.test(p)) ctx.addIssue({ code: "custom", message: "El PIN debe tener 4 dígitos." });
  })
  .transform((v) => ({ pin: String(v.pin ?? v.pin4 ?? "").trim() }));

export const pinDisableSchema = z
  .object({
    pin: pinInput.optional(),
    pin4: pinInput.optional(),
  })
  .superRefine((v, ctx) => {
    const p = String(v.pin ?? v.pin4 ?? "").trim();
    if (!/^\d{4}$/.test(p)) ctx.addIssue({ code: "custom", message: "El PIN debe tener 4 dígitos." });
  })
  .transform((v) => ({ pin: String(v.pin ?? v.pin4 ?? "").trim() }));

export const pinUnlockSchema = z
  .object({
    pin: pinInput.optional(),
    pin4: pinInput.optional(),
  })
  .superRefine((v, ctx) => {
    const p = String(v.pin ?? v.pin4 ?? "").trim();
    if (!/^\d{4}$/.test(p)) ctx.addIssue({ code: "custom", message: "El PIN debe tener 4 dígitos." });
  })
  .transform((v) => ({ pin: String(v.pin ?? v.pin4 ?? "").trim() }));

/* ✅ PIN opcional para permitir switch sin PIN cuando la joyería lo habilita
   ✅ Compat: pin | pin4 | "" */
export const pinSwitchSchema = z
  .object({
    targetUserId: z.string().min(1),
    pin: pinInput.optional(),
    pin4: pinInput.optional(),
  })
  .superRefine((v, ctx) => {
    const raw = String(v.pin ?? v.pin4 ?? "").trim();
    if (!raw) return; // opcional (cuando no se requiere)
    if (!/^\d{4}$/.test(raw)) ctx.addIssue({ code: "custom", message: "El PIN debe tener 4 dígitos." });
  })
  .transform((v) => ({
    targetUserId: v.targetUserId,
    pin: String(v.pin ?? v.pin4 ?? "").trim(), // puede ser ""
  }));

/* =========================
   🔐 CONFIG PIN / LOCK (JOYERÍA)
   ✅ Compat:
   - API actual: pinLockEnabled, pinLockTimeoutSec, pinLockRequireOnUserSwitch, quickSwitchEnabled
   - Front nuevo: enabled, timeoutMinutes, requireOnUserSwitch, quickSwitchEnabled
   ✅ PATCH: campos opcionales, pero debe venir al menos 1
========================= */
export const pinLockSettingsSchema = z
  .object({
    // canonical
    pinLockEnabled: boolInput.optional(),
    pinLockTimeoutSec: numInput.optional(),
    pinLockRequireOnUserSwitch: boolInput.optional(),
    quickSwitchEnabled: boolInput.optional(),

    // aliases (frontend)
    enabled: boolInput.optional(),
    timeoutMinutes: numInput.optional(),
    requireOnUserSwitch: boolInput.optional(),
  })
  .superRefine((v, ctx) => {
    const hasAny =
      v.pinLockEnabled !== undefined ||
      v.pinLockTimeoutSec !== undefined ||
      v.pinLockRequireOnUserSwitch !== undefined ||
      v.quickSwitchEnabled !== undefined ||
      v.enabled !== undefined ||
      v.timeoutMinutes !== undefined ||
      v.requireOnUserSwitch !== undefined;

    if (!hasAny) {
      ctx.addIssue({ code: "custom", message: "No hay campos para actualizar." });
      return;
    }

    // si viene timeout, validar rango (en segundos)
    const secRaw =
      v.pinLockTimeoutSec !== undefined
        ? v.pinLockTimeoutSec
        : v.timeoutMinutes !== undefined
        ? v.timeoutMinutes * 60
        : undefined;

    if (secRaw !== undefined) {
      if (!Number.isFinite(secRaw)) {
        ctx.addIssue({ code: "custom", message: "pinLockTimeoutSec inválido." });
        return;
      }
      const sec = Math.trunc(secRaw);
      if (sec < 10 || sec > 60 * 60 * 12) {
        ctx.addIssue({ code: "custom", message: "pinLockTimeoutSec fuera de rango." });
      }
    }
  })
  .transform((v) => {
    // normalizar aliases -> canonical
    const out: any = {};

    if (v.pinLockEnabled !== undefined) out.pinLockEnabled = v.pinLockEnabled;
    else if (v.enabled !== undefined) out.pinLockEnabled = v.enabled;

    const sec =
      v.pinLockTimeoutSec !== undefined
        ? Math.trunc(Number(v.pinLockTimeoutSec))
        : v.timeoutMinutes !== undefined
        ? Math.trunc(Number(v.timeoutMinutes) * 60)
        : undefined;

    if (sec !== undefined) out.pinLockTimeoutSec = sec;

    if (v.pinLockRequireOnUserSwitch !== undefined)
      out.pinLockRequireOnUserSwitch = v.pinLockRequireOnUserSwitch;
    else if (v.requireOnUserSwitch !== undefined) out.pinLockRequireOnUserSwitch = v.requireOnUserSwitch;

    if (v.quickSwitchEnabled !== undefined) out.quickSwitchEnabled = v.quickSwitchEnabled;

    return out;
  });
