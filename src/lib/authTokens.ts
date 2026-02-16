// tptech-backend/src/lib/authTokens.ts
import jwt from "jsonwebtoken";

function mustEnv(name: string) {
  const v = process.env[name];
  if (!v) throw new Error(`❌ ${name} no está configurado`);
  return v;
}

const JWT_SECRET = mustEnv("JWT_SECRET");
export const JWT_SECRET_SAFE: string = JWT_SECRET;

export const APP_URL = process.env.APP_URL || "http://localhost:5173";
export const JWT_ISSUER = process.env.JWT_ISSUER || "tptech";
export const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "tptech-web";

/**
 * ✅ expiresIn ahora usa el tipo correcto de jsonwebtoken
 * (evita TS2769 con @types/jsonwebtoken nuevos)
 */
export function signResetToken(
  userId: string,
  jti: string,
  expiresIn: jwt.SignOptions["expiresIn"]
) {
  return jwt.sign({ sub: userId, type: "reset", jti }, JWT_SECRET_SAFE, {
    expiresIn,
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  });
}

export function buildResetLink(resetToken: string) {
  return `${APP_URL}/reset-password?token=${encodeURIComponent(resetToken)}`;
}

/** ✅ Verifica token reset y devuelve payload normalizado */
export function verifyResetToken(token: string): { userId: string; jti: string } {
  const raw = jwt.verify(token, JWT_SECRET_SAFE, {
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  }) as any;

  const userId = String(raw?.sub || "").trim();
  const type = String(raw?.type || "").trim();
  const jti = String(raw?.jti || "").trim();

  if (!userId) throw new Error("Token inválido (sin sub).");
  if (type !== "reset") throw new Error("Token inválido (type).");
  if (!jti) throw new Error("Token inválido (sin jti).");

  return { userId, jti };
}
