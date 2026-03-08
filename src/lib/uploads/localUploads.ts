// tptech-backend/src/lib/uploads/localUploads.ts
import path from "node:path";
import fs from "node:fs";
import type { Request } from "express";

import { R2_ENABLED, getR2PublicBaseUrl } from "../storage/r2.js";

function stripSlashes(s: string) {
  return String(s || "").replace(/^\/+|\/+$/g, "");
}

function normalizeBaseUrl(s: string) {
  return String(s || "").trim().replace(/\/+$/g, "");
}

/**
 * ✅ Regla:
 * - Si R2_ENABLED => guardamos URL pública absoluta (CDN / custom domain)
 * - Si NO => guardamos ruta relativa /uploads/... para que el frontend la resuelva
 */
function isR2Enabled() {
  return Boolean(R2_ENABLED);
}

/**
 * Base público de R2:
 * - Solo R2_PUBLIC_BASE_URL
 * - Si no existe => ""
 */
function r2PublicBase() {
  return normalizeBaseUrl(getR2PublicBaseUrl() || "");
}

/**
 * Convierte (folder + filename) a valor persistible en DB.
 * - R2 => URL absoluta
 * - Local => ruta relativa /uploads/...
 */
export function toPublicUploadUrl(_req: Request, folder: string, filename: string) {
  const f = stripSlashes(folder);
  const name = String(filename || "").trim();
  if (!name) return "";

  if (isR2Enabled()) {
    const base = r2PublicBase();
    if (!base) return "";
    return `${base}/${encodeURI(f)}/${encodeURIComponent(name)}`;
  }

  return `/uploads/${encodeURI(f)}/${encodeURIComponent(name)}`;
}

/**
 * Solo para modo local: traduce una URL/ruta /uploads/... a path absoluto.
 * Si R2 está habilitado => devolvemos null.
 */
export function absLocalUploadFromUrl(url: string) {
  const u = String(url || "").trim();
  if (!u) return null;

  if (isR2Enabled()) return null;

  let rel = "";

  if (u.startsWith("/uploads/")) {
    rel = u.slice("/uploads/".length);
  } else {
    const idx = u.indexOf("/uploads/");
    if (idx === -1) return null;
    rel = u.slice(idx + "/uploads/".length);
  }

  const safeRel = rel.split("?")[0].split("#")[0];
  const abs = path.join(process.cwd(), "uploads", safeRel);
  return abs;
}

/**
 * Borra un archivo local si:
 * - estamos en modo local
 * - la URL/ruta matchea /uploads
 * - y matchea el prefixFolder esperado
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