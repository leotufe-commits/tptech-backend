// tptech-backend/src/lib/storage/r2.ts
import { S3Client } from "@aws-sdk/client-s3";
import type { S3ClientConfig } from "@aws-sdk/client-s3";

const accessKeyId = process.env.R2_ACCESS_KEY_ID;
const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;

export const R2_BUCKET = process.env.R2_BUCKET || "";
export const R2_PUBLIC_BASE_URL = process.env.R2_PUBLIC_BASE_URL || "";
export const R2_ENDPOINT = process.env.R2_ENDPOINT || ""; // ej: https://<accountid>.r2.cloudflarestorage.com
export const R2_REGION = process.env.R2_REGION || "auto";

const cfg: S3ClientConfig = {
  region: R2_REGION,
};

// endpoint (R2 usa endpoint custom)
if (R2_ENDPOINT) {
  cfg.endpoint = R2_ENDPOINT;
}

// credentials (solo si existen ambas)
if (accessKeyId && secretAccessKey) {
  cfg.credentials = { accessKeyId, secretAccessKey };
}

export const r2 = new S3Client(cfg);
