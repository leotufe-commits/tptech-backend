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

// Variables
export const R2_BUCKET = getEnv("R2_BUCKET");
export const R2_ENDPOINT = getEnv("R2_ENDPOINT");
export const R2_ACCESS_KEY_ID = getEnv("R2_ACCESS_KEY_ID");
export const R2_SECRET_ACCESS_KEY = getEnv("R2_SECRET_ACCESS_KEY");

// ✅ Esta es la URL pública que vas a usar para servir archivos (ideal: tu dominio/CDN)
export const R2_PUBLIC_BASE_URL = normalizeBaseUrl(process.env.R2_PUBLIC_BASE_URL || "");

// Región
export const R2_REGION = process.env.R2_REGION || "auto";

// ✅ R2 habilitado si hay config completa (sin importar si es prod o dev)
export const R2_ENABLED = Boolean(R2_ENDPOINT && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY && R2_BUCKET);

// 🔒 En producción son obligatorias
if (IS_PROD) {
  if (!R2_BUCKET) throw new Error("[R2] Missing required env var: R2_BUCKET");
  if (!R2_ENDPOINT) throw new Error("[R2] Missing required env var: R2_ENDPOINT");
  if (!R2_ACCESS_KEY_ID) throw new Error("[R2] Missing required env var: R2_ACCESS_KEY_ID");
  if (!R2_SECRET_ACCESS_KEY) throw new Error("[R2] Missing required env var: R2_SECRET_ACCESS_KEY");
}

// ✅ Solo crear cliente si hay config completa
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
 * ✅ Base público recomendado para armar URLs:
 * - Primero: R2_PUBLIC_BASE_URL (tu dominio/CDN)
 * - Si no está: vacío (y el resto del sistema puede caer a /uploads local)
 */
export function getR2PublicBaseUrl() {
  return R2_PUBLIC_BASE_URL;
}