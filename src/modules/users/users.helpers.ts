import type { Request, Response } from "express";
import { UserStatus } from "@prisma/client";
import path from "node:path";

export function requireTenantId(req: Request, res: Response): string | null {
  const tenantId = (req as any).tenantId as string | undefined;
  if (!tenantId) {
    res.status(400).json({ message: "Tenant no definido en el request." });
    return null;
  }
  return String(tenantId);
}

export function uniqStrings(arr: string[]) {
  return Array.from(new Set(arr));
}

export function normalizeEmail(raw: any) {
  return String(raw || "").toLowerCase().trim();
}

export function normalizeName(raw: any) {
  const s = String(raw || "").trim();
  return s.length ? s : null;
}

/**
 * undefined/null => undefined
 * "" => ""
 * normal => trim
 * (nunca null)
 */
export function normOpt(raw: any): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  const s = String(raw).trim();
  if (s.length === 0) return "";
  return s;
}

export function normStr(raw: any) {
  return String(raw ?? "").trim();
}

export function clampInt(v: any, def: number, min: number, max: number) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

export function toPublicUrl(relativePath: string) {
  const base = String(process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
  if (!base) return relativePath;
  const p = relativePath.startsWith("/") ? relativePath : `/${relativePath}`;
  return `${base}${p}`;
}

export function filenameFromAnyUrl(u: string) {
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

export function isValidUserStatus(v: any): v is UserStatus {
  return v === "ACTIVE" || v === "PENDING" || v === "BLOCKED";
}

export function isValidOverrideEffect(v: any): v is "ALLOW" | "DENY" {
  return v === "ALLOW" || v === "DENY";
}

export function isValidPin4(v: any): v is string {
  const s = String(v ?? "").trim();
  return /^[0-9]{4}$/.test(s);
}

export function safeAsciiFilename(name: string) {
  return (
    String(name || "archivo")
      .replace(/[\r\n"]/g, "")
      .replace(/[\/\\]/g, "_")
      .trim() || "archivo"
  );
}

export function contentDisposition(filename: string) {
  const fallback = safeAsciiFilename(filename);
  const utf8 = encodeURIComponent(String(filename || fallback));
  return `attachment; filename="${fallback}"; filename*=UTF-8''${utf8}`;
}

export function safeBasename(filename: string) {
  const safe = path.basename(String(filename || ""));
  return safe || "";
}
