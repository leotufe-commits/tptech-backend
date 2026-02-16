import { S3Client } from "@aws-sdk/client-s3";
import { env } from "../../config/env.js";

export const R2_BUCKET = String(env.R2_BUCKET || "");
export const R2_PUBLIC_BASE_URL = String(env.R2_PUBLIC_BASE_URL || "");

export const r2 = new S3Client({
  region: "auto",
  endpoint: env.R2_ENDPOINT,
  credentials: {
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
  },
});
