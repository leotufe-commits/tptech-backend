// src/modules/purchases/purchases.controller.ts
import type { Response } from "express";
import * as service from "./purchases.service.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) { if (!cond) { const e: any = new Error(msg); e.status = 400; throw e; } }

// ===========================================================================
// Purchases CRUD
// ===========================================================================

export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const skip = parseInt(String(req.query.skip ?? "0"), 10) || 0;
  const take = parseInt(String(req.query.take ?? "50"), 10) || 50;
  return res.json(
    await service.listPurchases(req.user.jewelryId, {
      supplierId: s(req.query.supplierId) || undefined,
      status: s(req.query.status) || undefined,
      q: s(req.query.q) || undefined,
      skip,
      take,
    })
  );
}

export async function getOne(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const id = s(req.params?.id);
  assert(id, "Id inválido.");
  return res.json(await service.getPurchase(id, req.user.jewelryId));
}

export async function create(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const userId = s(req.userId || req.user?.id || "");
  return res.status(201).json(await service.createPurchase(req.user.jewelryId, userId, req.body));
}

export async function confirm(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const id = s(req.params?.id);
  assert(id, "Id inválido.");
  const userId = s(req.userId || req.user?.id || "");
  return res.json(await service.confirmPurchase(id, req.user.jewelryId, userId));
}

export async function cancel(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const id = s(req.params?.id);
  assert(id, "Id inválido.");
  const userId = s(req.userId || req.user?.id || "");
  const cancelNote = s(req.body?.cancelNote || req.body?.note || "");
  return res.json(await service.cancelPurchase(id, req.user.jewelryId, userId, cancelNote));
}

// ===========================================================================
// Supplier payments
// ===========================================================================

export async function registerPayment(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const supplierId = s(req.params?.supplierId);
  assert(supplierId, "Id de proveedor inválido.");
  const userId = s(req.userId || req.user?.id || "");
  return res.status(201).json(
    await service.registerSupplierPayment(supplierId, req.user.jewelryId, userId, req.body)
  );
}

export async function registerMetalReturn(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const supplierId = s(req.params?.supplierId);
  assert(supplierId, "Id de proveedor inválido.");
  const userId = s(req.userId || req.user?.id || "");
  return res.status(201).json(
    await service.registerSupplierMetalReturn(supplierId, req.user.jewelryId, userId, req.body)
  );
}

export async function listPayments(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const supplierId = s(req.params?.supplierId);
  assert(supplierId, "Id de proveedor inválido.");
  const skip = parseInt(String(req.query.skip ?? "0"), 10) || 0;
  const take = parseInt(String(req.query.take ?? "50"), 10) || 50;
  const purchaseId = s(req.query.purchaseId) || undefined;
  return res.json(
    await service.listSupplierPayments(supplierId, req.user.jewelryId, { purchaseId, skip, take })
  );
}

export async function voidPayment(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const paymentId = s(req.params?.paymentId);
  assert(paymentId, "Id de pago inválido.");
  const userId = s(req.userId || req.user?.id || "");
  const reason = s(req.body?.reason || "");
  return res.json(await service.voidSupplierPayment(paymentId, req.user.jewelryId, userId, reason));
}

export async function applyCredit(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const supplierId = s(req.params?.supplierId);
  assert(supplierId, "Id de proveedor inválido.");
  const userId = s(req.userId || req.user?.id || "");
  return res.status(201).json(
    await service.applySupplierCredit(supplierId, req.user.jewelryId, userId, req.body)
  );
}
