// tptech-backend/src/modules/users/users.attachments.ts
import type { Request, Response } from "express";
import fs from "node:fs";
import path from "node:path";

import { prisma } from "../../lib/prisma.js";

/* =========================================================
   Config
========================================================= */
const PROJECT_ROOT = process.cwd();

function contentDisposition(filename: string) {
  const safe = String(filename || "archivo").replace(/[\r\n"]/g, "").slice(0, 180);
  const enc = encodeURIComponent(safe);
  return `attachment; filename="${safe}"; filename*=UTF-8''${enc}`;
}

function resolveAbsFromUrl(url: string) {
  const u = String(url || "").trim();

  // si viniera http(s) no hacemos proxy acá
  if (/^https?:\/\//i.test(u)) return null;

  const rel = u.replace(/^\/+/, ""); // saca "/" inicial
  const abs = path.resolve(PROJECT_ROOT, rel);

  // evita traversal
  const rootAbs = path.resolve(PROJECT_ROOT);
  if (!abs.startsWith(rootAbs + path.sep) && abs !== rootAbs) return null;

  return abs;
}

/** Soporta rutas con :id o :userId */
function getTargetUserId(req: Request) {
  return String((req.params as any).id || (req.params as any).userId || "");
}

/** url relativa desde root, ejemplo: "/uploads/user-attachments/xxx.jpg" */
function urlFromAbs(absPath: string) {
  const rootAbs = path.resolve(PROJECT_ROOT);
  const abs = path.resolve(absPath);

  if (abs.startsWith(rootAbs + path.sep)) {
    const rel = abs.slice(rootAbs.length + 1).replace(/\\/g, "/");
    return "/" + rel;
  }

  // fallback (no debería pasar)
  return "";
}

/* =========================================================
   Shared helpers
========================================================= */
async function assertUserInJewelry(userId: string, jewelryId: string) {
  const u = await prisma.user.findFirst({
    where: { id: userId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  return !!u;
}

function pickFiles(req: Request) {
  // multer .fields => req.files = { attachments: File[], "attachments[]": File[] }
  const filesObj = (req as any).files as
    | Record<
        string,
        Array<{
          originalname?: string;
          mimetype?: string;
          size?: number;
          filename?: string;
          path?: string;
        }>
      >
    | undefined;

  if (!filesObj) return [];

  const a = Array.isArray(filesObj["attachments"]) ? filesObj["attachments"] : [];
  const b = Array.isArray(filesObj["attachments[]"]) ? filesObj["attachments[]"] : [];
  return [...a, ...b].filter(Boolean);
}

/* =========================================================
   UPLOAD (ME)
   PUT /users/me/attachments
========================================================= */
export async function uploadMyAttachments(req: Request, res: Response) {
  try {
    const authUser = (req as any).user as { id?: string; jewelryId?: string } | undefined;
    const myId = String(authUser?.id || "");
    const jewelryId = String(authUser?.jewelryId || "");

    if (!myId || !jewelryId) return res.status(401).json({ message: "No autorizado." });

    const files = pickFiles(req);
    if (files.length === 0) return res.status(400).json({ message: "No se recibieron archivos." });

    const created = [];
    for (const f of files) {
      const abs = f.path ? path.resolve(String(f.path)) : "";
      const url = abs ? urlFromAbs(abs) : "";

      const row = await prisma.userAttachment.create({
        data: {
          userId: myId,
          url,
          filename: String(f.originalname || f.filename || "archivo"),
          mimeType: String(f.mimetype || "application/octet-stream"),
          size: Number(f.size || 0),
        },
        select: { id: true, url: true, filename: true, mimeType: true, size: true, createdAt: true },
      });

      created.push(row);
    }

    return res.status(201).json({ attachments: created });
  } catch (err: any) {
    return res.status(500).json({ message: err?.message || "Error subiendo archivos." });
  }
}

/* =========================================================
   UPLOAD (ADMIN)
   PUT /users/:id/attachments
========================================================= */
export async function uploadUserAttachments(req: Request, res: Response) {
  try {
    const authUser = (req as any).user as { jewelryId?: string } | undefined;
    const jewelryId = String(authUser?.jewelryId || "");
    if (!jewelryId) return res.status(401).json({ message: "No autorizado." });

    const userId = getTargetUserId(req);
    if (!userId) return res.status(400).json({ message: "Parámetros inválidos." });

    const ok = await assertUserInJewelry(userId, jewelryId);
    if (!ok) return res.status(404).json({ message: "Usuario no encontrado." });

    const files = pickFiles(req);
    if (files.length === 0) return res.status(400).json({ message: "No se recibieron archivos." });

    const created = [];
    for (const f of files) {
      const abs = f.path ? path.resolve(String(f.path)) : "";
      const url = abs ? urlFromAbs(abs) : "";

      const row = await prisma.userAttachment.create({
        data: {
          userId,
          url,
          filename: String(f.originalname || f.filename || "archivo"),
          mimeType: String(f.mimetype || "application/octet-stream"),
          size: Number(f.size || 0),
        },
        select: { id: true, url: true, filename: true, mimeType: true, size: true, createdAt: true },
      });

      created.push(row);
    }

    return res.status(201).json({ attachments: created });
  } catch (err: any) {
    return res.status(500).json({ message: err?.message || "Error subiendo archivos." });
  }
}

/* =========================================================
   DELETE
   DELETE /users/:id/attachments/:attachmentId
========================================================= */
export async function deleteUserAttachment(req: Request, res: Response) {
  try {
    const authUser = (req as any).user as { jewelryId?: string } | undefined;
    const jewelryId = String(authUser?.jewelryId || "");
    if (!jewelryId) return res.status(401).json({ message: "No autorizado." });

    const userId = getTargetUserId(req);
    const attachmentId = String((req.params as any).attachmentId || "");
    if (!userId || !attachmentId) return res.status(400).json({ message: "Parámetros inválidos." });

    const ok = await assertUserInJewelry(userId, jewelryId);
    if (!ok) return res.status(404).json({ message: "Usuario no encontrado." });

    const att = await prisma.userAttachment.findFirst({
      where: { id: attachmentId, userId },
      select: { id: true, url: true },
    });
    if (!att) return res.status(404).json({ message: "Adjunto no encontrado." });

    await prisma.userAttachment.delete({ where: { id: attachmentId } });

    // intenta borrar el archivo físico
    try {
      const abs = resolveAbsFromUrl(att.url);
      if (abs && fs.existsSync(abs)) fs.unlinkSync(abs);
    } catch {
      // no-op
    }

    return res.json({ ok: true });
  } catch (err: any) {
    return res.status(500).json({ message: err?.message || "Error eliminando adjunto." });
  }
}

/* =========================================================
   DOWNLOAD
   GET /users/:id/attachments/:attachmentId/download
========================================================= */
export async function downloadUserAttachment(req: Request, res: Response) {
  try {
    const authUser = (req as any).user as { jewelryId?: string } | undefined;
    const jewelryId = String(authUser?.jewelryId || "");
    if (!jewelryId) return res.status(401).json({ message: "No autorizado." });

    const userId = getTargetUserId(req);
    const attachmentId = String((req.params as any).attachmentId || "");
    if (!userId || !attachmentId) return res.status(400).json({ message: "Parámetros inválidos." });

    const ok = await assertUserInJewelry(userId, jewelryId);
    if (!ok) return res.status(404).json({ message: "Usuario no encontrado." });

    const att = await prisma.userAttachment.findFirst({
      where: { id: attachmentId, userId },
      select: { url: true, filename: true, mimeType: true, size: true },
    });
    if (!att) return res.status(404).json({ message: "Adjunto no encontrado." });

    const abs = resolveAbsFromUrl(att.url);
    if (!abs) return res.status(400).json({ message: "Ruta de archivo inválida." });
    if (!fs.existsSync(abs)) return res.status(404).json({ message: "Archivo no encontrado en el servidor." });

    res.setHeader("Content-Type", att.mimeType || "application/octet-stream");
    res.setHeader("Content-Disposition", contentDisposition(att.filename || "archivo"));
    res.setHeader("Cache-Control", "private, max-age=0, must-revalidate");
    if (typeof att.size === "number" && att.size > 0) res.setHeader("Content-Length", String(att.size));

    const stream = fs.createReadStream(abs);
    stream.on("error", () => {
      try {
        res.status(500).json({ message: "Error leyendo el archivo." });
      } catch {
        // no-op
      }
    });

    return stream.pipe(res);
  } catch (err: any) {
    return res.status(500).json({ message: err?.message || "Error descargando archivo." });
  }
}
