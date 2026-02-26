// tptech-backend/src/lib/uploads/localUploads.ts
import path from "node:path";
import fs from "node:fs";
import type { Request } from "express";

import { R2_ENABLED, getR2PublicBaseUrl } from "../storage/r2.js";

function stripSlashes(s: string) {
  return String(s || "").replace(/^\/+|\/+$/g, "");
}

function publicBaseUrl(req: Request) {
  const envBase = process.env.PUBLIC_BASE_URL?.replace(/\/+$/, "");
  return envBase || `${req.protocol}://${req.get("host")}`;
}

function normalizeBaseUrl(s: string) {
  return String(s || "").trim().replace(/\/+$/g, "");
}

/**
 * ✅ Regla “PRO”:
 * - Si R2_ENABLED => los archivos NO son locales, por lo tanto NO inventamos /uploads
 * - Si NO => usamos /uploads local
 */
function isR2Enabled() {
  return Boolean(R2_ENABLED);
}

/**
 * Base público de R2:
 * - Solo R2_PUBLIC_BASE_URL (dominio/CDN)
 * - Si no existe => "" (y el caller NO debe guardar una URL falsa)
 */
function r2PublicBase() {
  return normalizeBaseUrl(getR2PublicBaseUrl() || "");
}

/**
 * Convierte (folder + filename) a URL pública.
 * - Si R2 está habilitado => requiere R2_PUBLIC_BASE_URL
 * - Si no => /uploads local
 */
export function toPublicUploadUrl(req: Request, folder: string, filename: string) {
  const f = stripSlashes(folder);
  const name = String(filename || "").trim();
  if (!name) return "";

  // ✅ R2: solo si tenemos base pública
  if (isR2Enabled()) {
    const base = r2PublicBase();
    if (!base) {
      // IMPORTANTE: no devolvemos /uploads porque el archivo NO está local.
      // Devolvemos "" para que NO guardes URLs incorrectas.
      return "";
    }
    return `${base}/${encodeURI(f)}/${encodeURIComponent(name)}`;
  }

  // ✅ Local
  return `${publicBaseUrl(req)}/uploads/${encodeURI(f)}/${encodeURIComponent(name)}`;
}

/**
 * Solo para modo local: intenta traducir una URL /uploads/... a path absoluto.
 * Si R2 está habilitado => devolvemos null siempre (no es local).
 */
export function absLocalUploadFromUrl(url: string) {
  const u = String(url || "").trim();
  if (!u) return null;

  // ✅ Si R2 está habilitado, no es local
  if (isR2Enabled()) return null;

  // buscamos "/uploads/..."
  const idx = u.indexOf("/uploads/");
  if (idx === -1) return null;

  const rel = u.slice(idx + "/uploads/".length);
  const safeRel = rel.split("?")[0].split("#")[0];
  const abs = path.join(process.cwd(), "uploads", safeRel);
  return abs;
}

/**
 * Borra un archivo local si:
 * - estamos en modo local (no R2)
 * - la URL matchea /uploads
 * - y matchea el prefixFolder esperado (evitar borrar cualquier cosa)
 */
export async function safeDeleteLocalUploadByUrl(
  url: string | null | undefined,
  prefixFolder: string
) {
  const u = String(url || "").trim();
  if (!u) return;

  const abs = absLocalUploadFromUrl(u);
  if (!abs) return;

  const prefix = path.join(process.cwd(), "uploads", stripSlashes(prefixFolder)) + path.sep;

  const normalized = path.normalize(abs);
  if (!normalized.startsWith(prefix)) return;

  try {
    await fs.promises.unlink(normalized);
  } catch {
    // ignore
  }
}