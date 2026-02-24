// tptech-backend/src/lib/uploads/localUploads.ts
import path from "node:path";
import fs from "node:fs";
import type { Request } from "express";
import { r2, R2_PUBLIC_BASE_URL, R2_ENDPOINT } from "../storage/r2.js";

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
 * ✅ Regla “para siempre”:
 * - si R2 está configurado (r2 existe) => tratamos uploads como R2
 * - si no => tratamos uploads como local (/uploads)
 */
function isR2Enabled() {
  return Boolean(r2);
}

/**
 * Intenta obtener un base público para R2.
 * Preferencias:
 * 1) R2_PUBLIC_BASE_URL (ideal: tu dominio/CDN)
 * 2) R2_ENDPOINT (a veces sirve, depende cómo lo tengas publicado)
 *
 * Si no hay nada, devuelve "" y caemos a local.
 */
function r2PublicBase() {
  const b1 = normalizeBaseUrl(R2_PUBLIC_BASE_URL || "");
  if (b1) return b1;

  const b2 = normalizeBaseUrl(R2_ENDPOINT || "");
  if (b2) return b2;

  return "";
}

/**
 * Convierte (folder + filename) a URL pública.
 * - Si R2 está habilitado y hay base pública => usa R2
 * - Si no => usa /uploads local
 */
export function toPublicUploadUrl(req: Request, folder: string, filename: string) {
  const f = stripSlashes(folder);
  const name = String(filename || "").trim();
  if (!name) return "";

  if (isR2Enabled()) {
    const base = r2PublicBase();
    // Si está R2 pero no hay base pública, igual no rompemos: caemos a local
    if (base) return `${base}/${encodeURI(f)}/${encodeURIComponent(name)}`;
  }

  return `${publicBaseUrl(req)}/uploads/${encodeURI(f)}/${encodeURIComponent(name)}`;
}

/**
 * Solo para modo local: intenta traducir una URL /uploads/... a path absoluto.
 * Si es R2 => null
 */
export function absLocalUploadFromUrl(url: string) {
  const u = String(url || "").trim();
  if (!u) return null;

  // Si R2 está habilitado y la URL parece ser R2 (match con base pública), no es local
  if (isR2Enabled()) {
    const base = r2PublicBase();
    if (base && u.startsWith(base)) return null;
  }

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
 * - la URL es local (no R2)
 * - y matchea el prefixFolder esperado (para evitar borrar cualquier cosa)
 */
export async function safeDeleteLocalUploadByUrl(url: string | null | undefined, prefixFolder: string) {
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