import { z } from "zod";

const EnvSchema = z.object({
  NODE_ENV: z.string().optional().default("development"),
  PORT: z.coerce.number().optional().default(3001),

  JWT_SECRET: z.string().min(10, "JWT_SECRET debe tener al menos 10 caracteres"),

  // ✅ estos dos son los que te faltan (fix del build)
  JWT_ISSUER: z.string().optional().default("tptech"),
  JWT_AUDIENCE: z.string().optional().default("tptech-web"),

  CORS_ORIGIN: z.string().optional().default(""),

  // Prisma
  DATABASE_URL: z.string().min(1, "DATABASE_URL es requerida"),

  // Mail (si lo usás)
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().optional(),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),

  // opcional (vos lo usás)
  APP_URL: z.string().optional(),
});

export type Env = z.infer<typeof EnvSchema>;

export function getEnv(): Env {
  const parsed = EnvSchema.safeParse(process.env);

  if (!parsed.success) {
    console.error("❌ Error en variables de entorno:");
    console.error(parsed.error.flatten().fieldErrors);
    throw new Error("Variables de entorno inválidas. Revisá el .env / Render env vars.");
  }

  return parsed.data;
}
