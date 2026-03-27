// src/modules/printer-profiles/printer-profiles.controller.ts
import type { Response } from "express";
import {
  listPrinterProfiles, createPrinterProfile,
  updatePrinterProfile, deletePrinterProfile,
} from "./printer-profiles.service.js";

export async function list(req: any, res: Response) {
  res.json(await listPrinterProfiles(req.tenantId));
}

export async function create(req: any, res: Response) {
  res.status(201).json(await createPrinterProfile(req.tenantId, req.body));
}

export async function update(req: any, res: Response) {
  res.json(await updatePrinterProfile(req.params.id, req.tenantId, req.body));
}

export async function remove(req: any, res: Response) {
  await deletePrinterProfile(req.params.id, req.tenantId);
  res.json({ ok: true });
}
