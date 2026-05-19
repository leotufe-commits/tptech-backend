// src/modules/receipts/receipts.service.ts
// ============================================================================
// Lógica de Receipt — FASE 3 (DRAFT).
//
// Este módulo crea comprobantes en estado DRAFT sin disparar efectos:
//   · NO toca stock (no se crea ArticleMovement).
//   · NO crea CurrentAccountMovement.
//   · NO reserva número de ReceiptSeries (eso queda para el endpoint de
//     emisión — `POST /receipts/:id/issue` — fuera de esta fase).
//
// Como Receipt.code es NOT NULL y único por (jewelryId, seriesId, code),
// usamos un placeholder `DRAFT-${cuid}` mientras el comprobante esté en
// status=DRAFT. Al pasar a ISSUED se reemplaza por el código real
// formateado por la serie.
//
// Auto-provisión de ReceiptSeries: si todavía no hay una serie por defecto
// para (jewelryId, type, direction) — caso primer borrador del tenant —
// la creamos al vuelo con prefix "X" / pointOfSale "0001".
// ============================================================================

import { prisma } from "../../lib/prisma.js";
import type { Prisma } from "@prisma/client";
import { randomUUID } from "node:crypto";
import type { CreateReceiptDraftInput } from "./receipts.schemas.js";

/**
 * Resuelve (o crea) la serie por defecto para (jewelryId, type, direction).
 * Usa el prefix "X" y pointOfSale "0001" como serie temporal del tenant —
 * coherente con el patrón mock del frontend. Cuando el tenant configure
 * series reales, esta función seguirá devolviendo la primera disponible.
 */
async function resolveDefaultSeries(
  tx: Prisma.TransactionClient,
  jewelryId: string,
  type: "QUOTE" | "INVOICE" | "DELIVERY_NOTE" | "CREDIT_NOTE" | "DEBIT_NOTE",
  direction: "OUTBOUND" | "INBOUND",
) {
  // Preferir la primera activa del tenant para ese (type, direction).
  const found = await tx.receiptSeries.findFirst({
    where:   { jewelryId, type, direction, isActive: true, deletedAt: null },
    orderBy: { createdAt: "asc" },
    select:  { id: true, prefix: true, pointOfSale: true },
  });
  if (found) return found;

  // No existe: la creamos como serie por defecto.
  const created = await tx.receiptSeries.create({
    data: {
      jewelryId,
      name:        `${type} ${direction} (default)`,
      type,
      direction,
      prefix:      "X",
      pointOfSale: "0001",
      nextNumber:  1,
      isActive:    true,
    },
    select: { id: true, prefix: true, pointOfSale: true },
  });
  return created;
}

export async function createReceiptDraft(
  jewelryId: string,
  userId: string | null,
  body: CreateReceiptDraftInput,
) {
  const issueDate = body.issueDate ? new Date(body.issueDate) : new Date();
  const dueDate   = body.dueDate ? new Date(body.dueDate) : null;
  if (issueDate.toString() === "Invalid Date") {
    const err: any = new Error("issueDate inválida.");
    err.status = 400;
    throw err;
  }
  if (dueDate && dueDate.toString() === "Invalid Date") {
    const err: any = new Error("dueDate inválida.");
    err.status = 400;
    throw err;
  }

  return prisma.$transaction(async (tx) => {
    const series = await resolveDefaultSeries(tx, jewelryId, body.type, body.direction);

    // Placeholder único para DRAFT — se reemplaza al emitir.
    const draftCode = `DRAFT-${randomUUID()}`;

    const created = await tx.receipt.create({
      data: {
        jewelryId,
        seriesId:        series.id,
        code:            draftCode,
        type:            body.type,
        direction:       body.direction,
        status:          "DRAFT",

        counterpartyId:  body.counterpartyId || null,

        pricingSnapshot:  (body.pricingSnapshot ?? {}) as Prisma.InputJsonValue,
        currencySnapshot: (body.currencySnapshot ?? {}) as Prisma.InputJsonValue,
        currencyCode:     body.currencyCode || "",
        currencyRate:     body.currencyRate,

        subtotal:        body.subtotal,
        discountAmount:  body.discountAmount,
        taxAmount:       body.taxAmount,
        total:           body.total,
        totalBase:       body.totalBase,

        issueDate,
        dueDate,
        notes:           body.notes || "",
        terms:           body.terms || "",

        // status=DRAFT → issuedAt se setea al emitir, no acá.
        issuedById:      null,

        lines: body.lines.length === 0
          ? undefined
          : {
              create: body.lines.map((l, idx) => ({
                jewelryId,
                articleId:       l.articleId || null,
                variantId:       l.variantId || null,
                itemKind:        l.itemKind,
                name:            l.name || "",
                code:            l.code || "",
                sku:             l.sku || "",
                barcode:         l.barcode || "",

                quantity:        l.quantity,
                unitPrice:       l.unitPrice,
                subtotal:        l.subtotal,
                discountAmount:  l.discountAmount,
                lineTotal:       l.lineTotal,
                taxAmount:       l.taxAmount,
                totalWithTax:    l.totalWithTax,

                totalCost:       l.totalCost ?? null,
                totalMargin:     l.totalMargin ?? null,

                sortOrder:       l.sortOrder ?? idx,
                pricingSnapshot: (l.pricingSnapshot ?? {}) as Prisma.InputJsonValue,
              })),
            },
      },
      include: {
        lines: true,
        series: { select: { id: true, name: true, prefix: true, pointOfSale: true } },
      },
    });

    // Suprimimos el ESLint no-unused-var del userId — se usará al emitir
    // (`issuedById`). Lo dejamos por compatibilidad de firma para no romper
    // el controller cuando agreguemos el endpoint /issue.
    void userId;

    return created;
  });
}

// ===========================================================================
// Attachments — espejo del patrón de commercial-entities / sellers.
// Tenant scoping por jewelryId, soft-delete (deletedAt), upload vía R2/local.
// ===========================================================================

function s(v: any) {
  return String(v ?? "").trim();
}

function assert(cond: any, msg: string): asserts cond {
  if (!cond) {
    const err: any = new Error(msg);
    err.status = 400;
    throw err;
  }
}

const ATTACHMENT_SELECT = {
  id: true,
  filename: true,
  url: true,
  mimeType: true,
  size: true,
  label: true,
  createdAt: true,
} as const;

async function assertReceiptOwnership(receiptId: string, jewelryId: string) {
  const receipt = await prisma.receipt.findFirst({
    where: { id: receiptId, jewelryId },
    select: { id: true },
  });
  assert(receipt, "Comprobante no encontrado.");
}

export async function listAttachments(receiptId: string, jewelryId: string) {
  assert(receiptId, "Id de comprobante inválido.");
  assert(jewelryId, "Tenant inválido.");
  await assertReceiptOwnership(receiptId, jewelryId);
  return prisma.receiptAttachment.findMany({
    where: { receiptId, deletedAt: null },
    select: ATTACHMENT_SELECT,
    orderBy: { createdAt: "desc" as const },
  });
}

export async function addAttachment(
  receiptId: string,
  jewelryId: string,
  data: { filename: string; url: string; mimeType: string; size: number; label?: string; uploadedBy?: string }
) {
  assert(receiptId, "Id de comprobante inválido.");
  assert(jewelryId, "Tenant inválido.");
  assert(data?.filename, "Nombre de archivo inválido.");
  assert(data?.url, "URL inválida.");
  await assertReceiptOwnership(receiptId, jewelryId);

  return prisma.receiptAttachment.create({
    data: {
      receiptId,
      jewelryId,
      filename: data.filename,
      url: data.url,
      mimeType: data.mimeType || "",
      size: data.size || 0,
      label: s(data?.label),
      uploadedBy: s(data?.uploadedBy),
    },
    select: ATTACHMENT_SELECT,
  });
}

export async function updateAttachmentLabel(
  receiptId: string,
  attachmentId: string,
  jewelryId: string,
  label: string
) {
  assert(receiptId && attachmentId, "Ids inválidos.");
  assert(jewelryId, "Tenant inválido.");
  await assertReceiptOwnership(receiptId, jewelryId);

  const att = await prisma.receiptAttachment.findFirst({
    where: { id: attachmentId, receiptId, deletedAt: null },
    select: { id: true },
  });
  assert(att, "Adjunto no encontrado.");

  return prisma.receiptAttachment.update({
    where: { id: attachmentId },
    data: { label: s(label) },
    select: ATTACHMENT_SELECT,
  });
}

export async function removeAttachment(receiptId: string, attachmentId: string, jewelryId: string) {
  assert(receiptId && attachmentId, "Ids inválidos.");
  assert(jewelryId, "Tenant inválido.");
  await assertReceiptOwnership(receiptId, jewelryId);

  const att = await prisma.receiptAttachment.findFirst({
    where: { id: attachmentId, receiptId, deletedAt: null },
    select: { id: true },
  });
  assert(att, "Adjunto no encontrado.");

  await prisma.receiptAttachment.update({
    where: { id: attachmentId },
    data: { deletedAt: new Date() },
  });
  return { id: attachmentId };
}
