import { S3Client } from "@aws-sdk/client-s3";
import type { S3ClientConfig } from "@aws-sdk/client-s3";

function getEnv(name: string): string | undefined {
  const v = process.env[name];
  return v && v.trim() !== "" ? v : undefined;
}

const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";

// Variables
export const R2_BUCKET = getEnv("R2_BUCKET");
export const R2_ENDPOINT = getEnv("R2_ENDPOINT");
export const R2_ACCESS_KEY_ID = getEnv("R2_ACCESS_KEY_ID");
export const R2_SECRET_ACCESS_KEY = getEnv("R2_SECRET_ACCESS_KEY");

export const R2_PUBLIC_BASE_URL = process.env.R2_PUBLIC_BASE_URL || "";
export const R2_REGION = process.env.R2_REGION || "auto";

// 🔒 En producción son obligatorias
if (IS_PROD) {
  if (!R2_BUCKET) throw new Error("[R2] Missing required env var: R2_BUCKET");
  if (!R2_ENDPOINT) throw new Error("[R2] Missing required env var: R2_ENDPOINT");
  if (!R2_ACCESS_KEY_ID) throw new Error("[R2] Missing required env var: R2_ACCESS_KEY_ID");
  if (!R2_SECRET_ACCESS_KEY) throw new Error("[R2] Missing required env var: R2_SECRET_ACCESS_KEY");
}

// ✅ Solo crear cliente si hay config completa
let r2Client: S3Client | null = null;

if (R2_ENDPOINT && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY) {
  const cfg: S3ClientConfig = {
    region: R2_REGION,
    endpoint: R2_ENDPOINT,
    credentials: {
      accessKeyId: R2_ACCESS_KEY_ID,
      secretAccessKey: R2_SECRET_ACCESS_KEY,
    },
  };

  r2Client = new S3Client(cfg);
}

export const r2 = r2Client;
