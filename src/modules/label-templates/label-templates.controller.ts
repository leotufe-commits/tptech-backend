// src/modules/label-templates/label-templates.controller.ts
import type { Response } from "express";
import {
  listLabelTemplates, getLabelTemplate, createLabelTemplate,
  updateLabelTemplate, deleteLabelTemplate,
  addElement, updateElement, deleteElement, replaceElements,
} from "./label-templates.service.js";

export async function list(req: any, res: Response) {
  const data = await listLabelTemplates(req.tenantId);
  res.json(data);
}

export async function getOne(req: any, res: Response) {
  const data = await getLabelTemplate(req.params.id, req.tenantId);
  res.json(data);
}

export async function create(req: any, res: Response) {
  const data = await createLabelTemplate(req.tenantId, req.body);
  res.status(201).json(data);
}

export async function update(req: any, res: Response) {
  const data = await updateLabelTemplate(req.params.id, req.tenantId, req.body);
  res.json(data);
}

export async function remove(req: any, res: Response) {
  await deleteLabelTemplate(req.params.id, req.tenantId);
  res.json({ ok: true });
}

export async function addEl(req: any, res: Response) {
  const data = await addElement(req.params.id, req.tenantId, req.body);
  res.status(201).json(data);
}

export async function updateEl(req: any, res: Response) {
  const data = await updateElement(req.params.elementId, req.params.id, req.tenantId, req.body);
  res.json(data);
}

export async function deleteEl(req: any, res: Response) {
  await deleteElement(req.params.elementId, req.params.id, req.tenantId);
  res.json({ ok: true });
}

export async function replaceEl(req: any, res: Response) {
  const data = await replaceElements(req.params.id, req.tenantId, req.body.elements ?? []);
  res.json(data);
}
