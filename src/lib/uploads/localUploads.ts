// tptech-backend/src/lib/uploads/localUploads.ts
import type { Request } from "express";
import path from "node:path";
import fs from "node:fs/promises";
import fsSync from "node:fs";

/**
 * Estructura esperada de uploads:
 * /uploads/<scope>/<file>
 *
 * Ejemplos:
 * - /uploads/jewelry/xxxx.png
 * - /uploads/users/avatars/xxxx.png
 * - /uploads/avatars/legacy.png   (compat)
 */

function publicBaseUrl(req: Request) {
  const envBase = String(process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
  if (envBase) return envBase;

  return `${req.protocol}://${req.get("host")}`;
}

function filenameFromAnyUrl(u: string) {
  try {
    if (u.startsWith("http://") || u.startsWith("https://")) {
      const url = new URL(u);
      return decodeURIComponent(url.pathname.split("/").pop() || "");
    }
  } catch {
    // ignore
  }

  const parts = String(u || "").split("/");
  return decodeURIComponent(parts[parts.length - 1] || "");
}

function isLocalUploadsUrl(url: string) {
  const s = String(url || "");
  return s.includes("/uploads/");
}

/**
 * Construye URL pública a partir de un archivo subido local.
 * scope:
 *  - "jewelry"
 *  - "users/avatars"
 *  - "avatars" (legacy)
 */
export function toPublicUploadUrl(req: Request, scope: string, filename: string) {
  const base = publicBaseUrl(req);
  const cleanScope = String(scope || "").replace(/^\/+|\/+$/g, "");
  const safeName = path.basename(String(filename || ""));
  return `${base}/uploads/${cleanScope}/${encodeURIComponent(safeName)}`;
}

/**
 * Borra un archivo previo si:
 * - es URL local de este backend (/uploads/...)
 * - pertenece al scope indicado
 */
export async function safeDeleteLocalUploadByUrl(
  url: string | null,
  scope: string
) {
  if (!url) return;

  const s = String(url || "");
  if (!isLocalUploadsUrl(s)) return;

  const cleanScope = String(scope || "").replace(/^\/+|\/+$/g, "");
  const expected = `/uploads/${cleanScope}/`;
  if (!s.includes(expected)) return;

  const filename = filenameFromAnyUrl(s);
  if (!filename) return;

  const safeName = path.basename(filename);
  if (!safeName) return;

  const abs = path.join(process.cwd(), "uploads", cleanScope, safeName);

  try {
    if (!fsSync.existsSync(abs)) return;
    await fs.unlink(abs);
  } catch {
    // ignore
  }
}

/**
 * Convierte una URL/ruta de /uploads/... a un path ABSOLUTO local.
 * Soporta:
 * - URL completa: https://dominio.com/uploads/jewelry/xxx.png
 * - Ruta: /uploads/jewelry/xxx.png
 * - Relativo: uploads/jewelry/xxx.png
 */
export function absLocalUploadFromUrl(urlOrPath: string) {
  const s = String(urlOrPath || "").trim();
  if (!s) return "";

  if (path.isAbsolute(s)) return s;

  let pathname = s;

  try {
    if (s.startsWith("http://") || s.startsWith("https://")) {
      pathname = new URL(s).pathname;
    }
  } catch {
    // ignore
  }

  pathname = pathname.replace(/\\/g, "/");

  const marker = "/uploads/";
  const idx = pathname.indexOf(marker);

  const rel =
    idx >= 0
      ? pathname.slice(idx + marker.length)
      : pathname.replace(/^\/+/, "").replace(/^uploads\/+/, "");

  return path.join(process.cwd(), "uploads", rel);
}