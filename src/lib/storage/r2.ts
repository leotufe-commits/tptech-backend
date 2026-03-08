// tptech-backend/src/lib/storage/r2.ts
import { S3Client } from "@aws-sdk/client-s3";
import type { S3ClientConfig } from "@aws-sdk/client-s3";

function getEnv(name: string): string | undefined {
  const v = process.env[name];
  return v && v.trim() !== "" ? v : undefined;
}

function normalizeBaseUrl(v: string) {
  return String(v || "").trim().replace(/\/+$/g, "");
}

const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";

/**
 * STORAGE_DRIVER:
 * - "auto"  => en desarrollo puede usar R2 si está configurado, si no local
 * - "r2"    => obliga R2 (si falta config, ERROR)
 * - "local" => fuerza local (ignora R2)
 *
 * ✅ Regla endurecida:
 * En producción NO permitimos fallback silencioso a local.
 * Si querés comercializar TPTech, producción debe correr con STORAGE_DRIVER=r2.
 */
const STORAGE_DRIVER = String(getEnv("STORAGE_DRIVER") || "auto")
  .trim()
  .toLowerCase();

export const R2_BUCKET = getEnv("R2_BUCKET");
export const R2_ENDPOINT = getEnv("R2_ENDPOINT");
export const R2_ACCESS_KEY_ID = getEnv("R2_ACCESS_KEY_ID");
export const R2_SECRET_ACCESS_KEY = getEnv("R2_SECRET_ACCESS_KEY");
export const R2_PUBLIC_BASE_URL = normalizeBaseUrl(getEnv("R2_PUBLIC_BASE_URL") || "");
export const R2_REGION = process.env.R2_REGION || "auto";

const FORCE_LOCAL = STORAGE_DRIVER === "local";
const FORCE_R2 = STORAGE_DRIVER === "r2";
const AUTO_MODE = STORAGE_DRIVER === "auto";

const R2_CONFIG_OK = Boolean(
  R2_ENDPOINT && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY && R2_BUCKET
);

function missingVars() {
  const missing: string[] = [];
  if (!R2_BUCKET) missing.push("R2_BUCKET");
  if (!R2_ENDPOINT) missing.push("R2_ENDPOINT");
  if (!R2_ACCESS_KEY_ID) missing.push("R2_ACCESS_KEY_ID");
  if (!R2_SECRET_ACCESS_KEY) missing.push("R2_SECRET_ACCESS_KEY");
  return missing;
}

function missingPublicBase() {
  return !R2_PUBLIC_BASE_URL;
}

/**
 * ✅ Política final:
 * - Producción:
 *   - local: prohibido
 *   - auto: prohibido
 *   - r2: obligatorio y completo
 *
 * - Desarrollo:
 *   - local: permitido
 *   - auto: permitido
 *   - r2: permitido si está completo
 */
if (IS_PROD) {
  if (FORCE_LOCAL) {
    throw new Error(
      "[R2] STORAGE_DRIVER=local no está permitido en producción. Usá STORAGE_DRIVER=r2."
    );
  }

  if (AUTO_MODE) {
    throw new Error(
      "[R2] STORAGE_DRIVER=auto no está permitido en producción. Usá STORAGE_DRIVER=r2 con configuración completa."
    );
  }

  if (FORCE_R2) {
    if (!R2_CONFIG_OK) {
      throw new Error(
        `[R2] STORAGE_DRIVER=r2 pero falta configuración: ${missingVars().join(", ")}`
      );
    }

    if (missingPublicBase()) {
      throw new Error(
        "[R2] STORAGE_DRIVER=r2 pero falta R2_PUBLIC_BASE_URL (necesario para URLs públicas)."
      );
    }
  }
} else {
  if (FORCE_R2) {
    if (!R2_CONFIG_OK) {
      throw new Error(
        `[R2] STORAGE_DRIVER=r2 pero falta configuración: ${missingVars().join(", ")}`
      );
    }

    if (missingPublicBase()) {
      throw new Error(
        "[R2] STORAGE_DRIVER=r2 pero falta R2_PUBLIC_BASE_URL (necesario para URLs públicas)."
      );
    }
  }

  if (AUTO_MODE && !R2_CONFIG_OK) {
    console.warn(
      `[R2] R2 no configurado (${missingVars().join(
        ", "
      )}). STORAGE_DRIVER=auto → usando storage local.`
    );
  }

  if (AUTO_MODE && R2_CONFIG_OK && missingPublicBase()) {
    console.warn(
      "[R2] R2 está configurado pero falta R2_PUBLIC_BASE_URL. STORAGE_DRIVER=auto continuará, pero no deberías usar esta configuración fuera de desarrollo."
    );
  }
}

/**
 * ✅ R2 habilitado solo si:
 * - no forzás local
 * - y hay config técnica completa
 *
 * En producción ya garantizamos arriba que solo exista modo r2 válido.
 */
export const R2_ENABLED = !FORCE_LOCAL && R2_CONFIG_OK;

export const r2: S3Client | null = R2_ENABLED
  ? new S3Client({
      region: R2_REGION,
      endpoint: R2_ENDPOINT,
      forcePathStyle: true,
      credentials: {
        accessKeyId: R2_ACCESS_KEY_ID!,
        secretAccessKey: R2_SECRET_ACCESS_KEY!,
      },
    } satisfies S3ClientConfig)
  : null;

export function getR2PublicBaseUrl() {
  return R2_PUBLIC_BASE_URL;
}