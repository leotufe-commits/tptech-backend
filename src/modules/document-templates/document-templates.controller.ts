// src/modules/document-templates/document-templates.controller.ts

import type { Request, Response } from "express";
import { DocumentKind } from "@prisma/client";
import { VALID_KINDS, buildDefaultTemplateResponse } from "./document-templates.constants.js";
import {
  getOrCreateTemplate,
  saveTemplate,
  resetTemplate,
} from "./document-templates.service.js";

const VALID_LAYOUT_TYPES = ["A4", "TICKET", "COMPACT"] as const;
type LayoutType = typeof VALID_LAYOUT_TYPES[number];

function kind(req: Request): DocumentKind | null {
  const k = (String(req.params.kind ?? "")).toUpperCase();
  return VALID_KINDS.includes(k as DocumentKind) ? (k as DocumentKind) : null;
}

function layout(req: Request): LayoutType {
  const l = (String(req.query.layout ?? "A4")).toUpperCase() as LayoutType;
  return VALID_LAYOUT_TYPES.includes(l) ? l : "A4";
}

export async function getTemplate(req: Request, res: Response) {
  const k = kind(req);
  if (!k) return res.status(400).json({ message: "Tipo de documento inválido." });
  try {
    const template = await getOrCreateTemplate((req as any).tenantId, k, layout(req));
    return res.json({ template });
  } catch (err) {
    console.error("[document-templates] getTemplate error:", err);
    return res.json({ template: buildDefaultTemplateResponse(k, layout(req)), _fallback: true });
  }
}

export async function putTemplate(req: Request, res: Response) {
  const k = kind(req);
  if (!k) return res.status(400).json({ message: "Tipo de documento inválido." });
  try {
    const template = await saveTemplate((req as any).tenantId, k, req.body ?? {}, layout(req));
    return res.json({ template });
  } catch (err) {
    console.error("[document-templates] putTemplate error:", err);
    return res.status(500).json({ message: "Error al guardar la plantilla." });
  }
}

export async function patchTemplate(req: Request, res: Response) {
  const k = kind(req);
  if (!k) return res.status(400).json({ message: "Tipo de documento inválido." });
  try {
    const template = await saveTemplate((req as any).tenantId, k, req.body ?? {}, layout(req));
    return res.json({ template });
  } catch (err) {
    console.error("[document-templates] patchTemplate error:", err);
    return res.status(500).json({ message: "Error al guardar la plantilla." });
  }
}

export async function resetTemplateHandler(req: Request, res: Response) {
  const k = kind(req);
  if (!k) return res.status(400).json({ message: "Tipo de documento inválido." });
  try {
    const template = await resetTemplate((req as any).tenantId, k, layout(req));
    return res.json({ template });
  } catch (err) {
    console.error("[document-templates] resetTemplateHandler error:", err);
    return res.status(500).json({ message: "Error al restaurar la plantilla." });
  }
}
