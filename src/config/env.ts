import { z } from "zod";

const EnvSchema = z.object({
  NODE_ENV: z.string().optional().default("development"),
  PORT: z.coerce.number().optional().default(3001),

  JWT_SECRET: z.string().min(10, "JWT_SECRET debe tener al menos 10 caracteres"),

  JWT_ISSUER: z.string().optional().default("tptech"),
  JWT_AUDIENCE: z.string().optional().default("tptech-web"),

  CORS_ORIGIN: z.string().optional().default(""),

  // =========================
  // Prisma
  // =========================
  DATABASE_URL: z.string().min(1, "DATABASE_URL es requerida"),

  // =========================
  // Mail
  // =========================
  MAIL_MODE: z.enum(["preview", "console", "production"]).optional().default("preview"),
  MAIL_FROM: z.string().optional().default("no-reply@tptech.local"),
  MAIL_APP_NAME: z.string().optional().default("TPTech"),

  // Postmark — ambos nombres aceptados (SERVER_TOKEN es el correcto en código)
  POSTMARK_SERVER_TOKEN: z.string().optional(),
  POSTMARK_API_TOKEN: z.string().optional(), // alias por compatibilidad

  // Dev link en respuesta de invitación — false por defecto, solo activar en local
  MAIL_EXPOSE_DEV_LINK: z
    .string()
    .optional()
    .default("false")
    .transform((v) => v === "true"),

  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().optional(),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),

  // =========================
  // App
  // =========================
  APP_URL: z.string().url("APP_URL debe ser una URL válida (ej: https://tptech.onrender.com)").optional().default("http://localhost:5173"),

  // =========================
  // R2 (Cloudflare Storage)
  // 👉 Ahora opcionales en local
  // =========================
  R2_ENDPOINT: z.string().optional(),
  R2_ACCESS_KEY_ID: z.string().optional(),
  R2_SECRET_ACCESS_KEY: z.string().optional(),
  R2_BUCKET: z.string().optional(),
  R2_PUBLIC_BASE_URL: z.string().optional().default(""),
});

export type Env = z.infer<typeof EnvSchema>;

export function getEnv(): Env {
  // ✅ Normalizar alias Postmark ANTES del parse, para que Zod lo vea como POSTMARK_SERVER_TOKEN
  if (!process.env.POSTMARK_SERVER_TOKEN && process.env.POSTMARK_API_TOKEN) {
    process.env.POSTMARK_SERVER_TOKEN = process.env.POSTMARK_API_TOKEN;
  }

  const parsed = EnvSchema.safeParse(process.env);

  if (!parsed.success) {
    console.error("❌ Error en variables de entorno:");
    console.error(parsed.error.flatten().fieldErrors);
    throw new Error("Variables de entorno inválidas. Revisá el .env / Render env vars.");
  }

  // ✅ Validación cruzada: MAIL_MODE=production requiere configuración real
  if (parsed.data.MAIL_MODE === "production") {
    if (!parsed.data.POSTMARK_SERVER_TOKEN) {
      throw new Error(
        "❌ MAIL_MODE=production requiere configurar POSTMARK_SERVER_TOKEN (o POSTMARK_API_TOKEN como alias)."
      );
    }

    const fromDomain = parsed.data.MAIL_FROM.split("@")[1] ?? "";
    if (!fromDomain || fromDomain.endsWith(".local") || parsed.data.MAIL_FROM === "no-reply@tptech.local") {
      throw new Error(
        `❌ MAIL_MODE=production: MAIL_FROM "${parsed.data.MAIL_FROM}" no es válido para producción. Configurá un dominio real (ej: no-reply@tujoyeria.com).`
      );
    }
  }

  return parsed.data;
}

// ✅ Export listo para usar en todo el backend
export const env = getEnv();
