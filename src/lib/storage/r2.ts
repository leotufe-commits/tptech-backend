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
 * - "auto"  => usa R2 si está todo configurado, si no cae a local
 * - "r2"    => obliga R2 (si falta config, ERROR)
 * - "local" => fuerza local (ignora R2)
 */
const STORAGE_DRIVER = String(getEnv("STORAGE_DRIVER") || "auto")
  .trim()
  .toLowerCase();

export const R2_BUCKET = getEnv("R2_BUCKET");
export const R2_ENDPOINT = getEnv("R2_ENDPOINT");
export const R2_ACCESS_KEY_ID = getEnv("R2_ACCESS_KEY_ID");
export const R2_SECRET_ACCESS_KEY = getEnv("R2_SECRET_ACCESS_KEY");

// ✅ URL pública (tu dominio/CDN). Si no está, queda ""
export const R2_PUBLIC_BASE_URL = normalizeBaseUrl(getEnv("R2_PUBLIC_BASE_URL") || "");

// Región (para R2 suele ser "auto")
export const R2_REGION = process.env.R2_REGION || "auto";

// ✅ Config completa
const R2_CONFIG_OK = Boolean(
  R2_ENDPOINT && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY && R2_BUCKET
);

// ✅ Driver efectivo
const FORCE_LOCAL = STORAGE_DRIVER === "local";
const FORCE_R2 = STORAGE_DRIVER === "r2";

// ✅ R2 habilitado si:
// - no forzás local
// - y hay config completa
export const R2_ENABLED = !FORCE_LOCAL && R2_CONFIG_OK;

/**
 * En producción:
 * - Si STORAGE_DRIVER=r2 => es obligatorio tener R2 configurado
 * - Si STORAGE_DRIVER=auto => NO crashea si falta (solo avisa)
 */
function missingVars() {
  const missing: string[] = [];
  if (!R2_BUCKET) missing.push("R2_BUCKET");
  if (!R2_ENDPOINT) missing.push("R2_ENDPOINT");
  if (!R2_ACCESS_KEY_ID) missing.push("R2_ACCESS_KEY_ID");
  if (!R2_SECRET_ACCESS_KEY) missing.push("R2_SECRET_ACCESS_KEY");
  return missing;
}

if (IS_PROD) {
  if (FORCE_R2 && !R2_CONFIG_OK) {
    throw new Error(
      `[R2] STORAGE_DRIVER=r2 pero falta configuración: ${missingVars().join(", ")}`
    );
  }

  if (STORAGE_DRIVER === "auto" && !R2_CONFIG_OK) {
    // ✅ No rompemos el deploy: solo informamos que se usará local
    console.warn(
      `[R2] R2 no configurado (${missingVars().join(
        ", "
      )}). STORAGE_DRIVER=auto → usando storage local.`
    );
  }
}

// ✅ Crear cliente solo si se va a usar R2
export const r2: S3Client | null = R2_ENABLED
  ? new S3Client({
      region: R2_REGION,
      endpoint: R2_ENDPOINT,
      credentials: {
        accessKeyId: R2_ACCESS_KEY_ID!,
        secretAccessKey: R2_SECRET_ACCESS_KEY!,
      },
    } satisfies S3ClientConfig)
  : null;

/**
 * Base público recomendado para armar URLs:
 * - Primero: R2_PUBLIC_BASE_URL (tu dominio/CDN)
 * - Si no está: ""
 */
export function getR2PublicBaseUrl() {
  return R2_PUBLIC_BASE_URL;
}