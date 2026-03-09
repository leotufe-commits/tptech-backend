import { prisma } from "../../lib/prisma.js";
import type { PaymentMethodType, PaymentAdjustmentType } from "@prisma/client";

function s(v: any) { return String(v ?? "").trim(); }

function assert(cond: any, msg: string): asserts cond {
  if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; }
}

const VALID_TYPES: PaymentMethodType[] = ["CASH", "DEBIT_CARD", "CREDIT_CARD", "TRANSFER", "QR", "OTHER"];
const VALID_ADJ: PaymentAdjustmentType[] = ["NONE", "PERCENTAGE", "FIXED_AMOUNT"];

const PM_SELECT = {
  id: true, jewelryId: true, name: true, code: true, type: true,
  adjustmentType: true, adjustmentValue: true,
  isFavorite: true, isActive: true, sortOrder: true, notes: true,
  deletedAt: true, createdAt: true, updatedAt: true,
  installmentPlans: {
    where: { isActive: true },
    select: { id: true, installments: true, interestRate: true, isActive: true, sortOrder: true },
    orderBy: { installments: "asc" as const },
  },
} as const;

function parseInstallmentPlans(plans: any[], jewelryId: string, paymentMethodId?: string) {
  if (!Array.isArray(plans)) return [];
  return plans
    .filter((p) => p && Number.isFinite(Number(p.installments)) && Number(p.installments) > 0)
    .map((p, i) => ({
      jewelryId,
      paymentMethodId: paymentMethodId ?? "",
      installments: Number(p.installments),
      interestRate: String(Math.max(0, parseFloat(String(p.interestRate ?? 0)) || 0)),
      isActive: p.isActive !== false,
      sortOrder: i,
    }));
}

export async function listPaymentMethods(jewelryId: string) {
  assert(jewelryId, "Tenant inválido.");
  return prisma.paymentMethod.findMany({
    where: { jewelryId, deletedAt: null },
    select: PM_SELECT,
    orderBy: [{ isFavorite: "desc" }, { sortOrder: "asc" }, { name: "asc" }],
  });
}

export async function createPaymentMethod(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");
  const name = s(data?.name);
  assert(name, "Nombre requerido.");

  const type: PaymentMethodType = VALID_TYPES.includes(data?.type) ? data.type : "OTHER";
  const adjustmentType: PaymentAdjustmentType = VALID_ADJ.includes(data?.adjustmentType) ? data.adjustmentType : "NONE";
  const adjustmentValue = adjustmentType !== "NONE" ? String(parseFloat(String(data?.adjustmentValue ?? 0)) || 0) : null;
  if (adjustmentType !== "NONE") assert(adjustmentValue !== null, "Valor de ajuste requerido.");

  const code = s(data?.code) || await generateCode(jewelryId, name);
  const isFavorite = data?.isFavorite === true;
  const sortOrder = Number(data?.sortOrder ?? 0) || 0;
  const plans = parseInstallmentPlans(data?.installmentPlans ?? [], jewelryId);

  if (isFavorite) {
    await prisma.paymentMethod.updateMany({ where: { jewelryId, deletedAt: null, isFavorite: true }, data: { isFavorite: false } });
  }

  return prisma.paymentMethod.create({
    data: {
      jewelryId, name, code, type, adjustmentType,
      adjustmentValue: adjustmentValue ?? undefined,
      isFavorite, isActive: true, sortOrder,
      notes: s(data?.notes),
      installmentPlans: { create: plans.map(({ paymentMethodId: _, ...p }) => p) },
    },
    select: PM_SELECT,
  });
}

export async function updatePaymentMethod(id: string, jewelryId: string, data: any) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const existing = await prisma.paymentMethod.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true } });
  assert(existing, "Medio de pago no encontrado.");

  const name = s(data?.name);
  assert(name, "Nombre requerido.");
  const type: PaymentMethodType = VALID_TYPES.includes(data?.type) ? data.type : "OTHER";
  const adjustmentType: PaymentAdjustmentType = VALID_ADJ.includes(data?.adjustmentType) ? data.adjustmentType : "NONE";
  const adjustmentValue = adjustmentType !== "NONE" ? String(parseFloat(String(data?.adjustmentValue ?? 0)) || 0) : null;
  const isFavorite = data?.isFavorite === true;
  const isActive = data?.isActive === false ? false : true;
  const code = s(data?.code) || await generateCode(jewelryId, name);

  if (isFavorite) {
    await prisma.paymentMethod.updateMany({ where: { jewelryId, deletedAt: null, isFavorite: true, id: { not: id } }, data: { isFavorite: false } });
  }

  // Replace installment plans
  const plans = parseInstallmentPlans(data?.installmentPlans ?? [], jewelryId, id);
  await prisma.paymentInstallmentPlan.deleteMany({ where: { paymentMethodId: id } });

  return prisma.paymentMethod.update({
    where: { id },
    data: {
      name, code, type, adjustmentType,
      adjustmentValue: adjustmentValue ?? undefined,
      isFavorite, isActive, sortOrder: Number(data?.sortOrder ?? 0) || 0,
      notes: s(data?.notes),
      installmentPlans: plans.length > 0
        ? { create: plans.map(({ paymentMethodId: _, ...p }) => p) }
        : undefined,
    },
    select: PM_SELECT,
  });
}

export async function clonePaymentMethod(id: string, jewelryId: string) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const original = await prisma.paymentMethod.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { ...PM_SELECT, installmentPlans: { select: { installments: true, interestRate: true, isActive: true, sortOrder: true } } },
  });
  assert(original, "Medio de pago no encontrado.");

  const newCode = await generateCode(jewelryId, original.name + " copia");
  return prisma.paymentMethod.create({
    data: {
      jewelryId, name: `${original.name} (copia)`, code: newCode,
      type: original.type, adjustmentType: original.adjustmentType,
      adjustmentValue: original.adjustmentValue ?? undefined,
      isFavorite: false, isActive: false,
      sortOrder: original.sortOrder, notes: original.notes,
      installmentPlans: {
        create: original.installmentPlans.map((p) => ({ jewelryId, installments: p.installments, interestRate: p.interestRate, isActive: p.isActive, sortOrder: p.sortOrder })),
      },
    },
    select: PM_SELECT,
  });
}

export async function togglePaymentMethod(id: string, jewelryId: string) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const pm = await prisma.paymentMethod.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true, isActive: true } });
  assert(pm, "Medio de pago no encontrado.");
  return prisma.paymentMethod.update({ where: { id }, data: { isActive: !pm.isActive }, select: PM_SELECT });
}

export async function setFavoritePaymentMethod(id: string, jewelryId: string) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const pm = await prisma.paymentMethod.findFirst({ where: { id, jewelryId, deletedAt: null, isActive: true }, select: { id: true } });
  assert(pm, "Medio de pago no encontrado o inactivo.");
  await prisma.paymentMethod.updateMany({ where: { jewelryId, deletedAt: null }, data: { isFavorite: false } });
  return prisma.paymentMethod.update({ where: { id }, data: { isFavorite: true }, select: PM_SELECT });
}

export async function deletePaymentMethod(id: string, jewelryId: string) {
  assert(id, "Id inválido."); assert(jewelryId, "Tenant inválido.");
  const pm = await prisma.paymentMethod.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true, isFavorite: true } });
  assert(pm, "Medio de pago no encontrado.");
  if (pm.isFavorite) {
    // unset favorite before deleting
    await prisma.paymentMethod.updateMany({ where: { jewelryId, deletedAt: null }, data: { isFavorite: false } });
  }
  return prisma.paymentMethod.update({ where: { id }, data: { deletedAt: new Date(), isActive: false }, select: { id: true } });
}

async function generateCode(jewelryId: string, name: string): Promise<string> {
  const prefix = name.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9]/g, "").toUpperCase().substring(0, 5).padEnd(3, "X");
  const count = await prisma.paymentMethod.count({ where: { jewelryId } });
  return `${prefix}${String(count + 1).padStart(2, "0")}`;
}
