import { prisma } from "../../lib/prisma.js";
import type { TaxType, TaxCalculationType, TaxApplyOn } from "@prisma/client";

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

function toDecimalOrNull(v: any): string | null {
  const n = parseFloat(String(v ?? ""));
  return Number.isFinite(n) && n >= 0 ? String(n) : null;
}

const VALID_TAX_TYPES: TaxType[] = ["IVA", "INTERNAL", "PERCEPTION", "RETENTION", "OTHER"];
const VALID_CALC_TYPES: TaxCalculationType[] = ["PERCENTAGE", "FIXED_AMOUNT", "PERCENTAGE_PLUS_FIXED"];
const VALID_APPLY_ON: TaxApplyOn[] = ["TOTAL", "METAL", "HECHURA", "METAL_Y_HECHURA", "SUBTOTAL_AFTER_DISCOUNT", "SUBTOTAL_BEFORE_DISCOUNT"];

function parseTaxData(data: any) {
  const name = s(data?.name);
  const code = s(data?.code);
  const taxType: TaxType = VALID_TAX_TYPES.includes(data?.taxType) ? data.taxType : "OTHER";
  const calculationType: TaxCalculationType = VALID_CALC_TYPES.includes(data?.calculationType) ? data.calculationType : "PERCENTAGE";
  const applyOn: TaxApplyOn = VALID_APPLY_ON.includes(data?.applyOn) ? data.applyOn : "TOTAL";
  const rate = toDecimalOrNull(data?.rate);
  const fixedAmount = toDecimalOrNull(data?.fixedAmount);
  const includedInPrice = data?.includedInPrice === true;
  const validFrom = data?.validFrom ? new Date(data.validFrom) : null;
  const validTo = data?.validTo ? new Date(data.validTo) : null;
  const sortOrder = Number(data?.sortOrder ?? 0) || 0;
  const notes = s(data?.notes);
  return { name, code, taxType, calculationType, applyOn, rate, fixedAmount, includedInPrice, validFrom, validTo, sortOrder, notes };
}

const SELECT = {
  id: true,
  jewelryId: true,
  name: true,
  code: true,
  taxType: true,
  calculationType: true,
  rate: true,
  fixedAmount: true,
  applyOn: true,
  includedInPrice: true,
  validFrom: true,
  validTo: true,
  isActive: true,
  sortOrder: true,
  notes: true,
  deletedAt: true,
  createdAt: true,
  updatedAt: true,
} as const;

export async function listTaxes(jewelryId: string) {
  assert(jewelryId, "Tenant inválido.");
  return prisma.tax.findMany({
    where: { jewelryId, deletedAt: null },
    select: SELECT,
    orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
  });
}

export async function createTax(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");
  const parsed = parseTaxData(data);
  assert(parsed.name, "Nombre requerido.");

  // Auto-generate code if empty
  const code = parsed.code || await generateTaxCode(jewelryId, parsed.name);

  // Validate: PERCENTAGE needs rate, FIXED_AMOUNT needs fixedAmount
  if (parsed.calculationType === "PERCENTAGE" || parsed.calculationType === "PERCENTAGE_PLUS_FIXED") {
    assert(parsed.rate !== null, "Se requiere una tasa porcentual.");
  }
  if (parsed.calculationType === "FIXED_AMOUNT" || parsed.calculationType === "PERCENTAGE_PLUS_FIXED") {
    assert(parsed.fixedAmount !== null, "Se requiere un monto fijo.");
  }

  return prisma.tax.create({
    data: { jewelryId, ...parsed, code, isActive: true },
    select: SELECT,
  });
}

export async function updateTax(id: string, jewelryId: string, data: any) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const existing = await prisma.tax.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true } });
  assert(existing, "Impuesto no encontrado.");

  const parsed = parseTaxData(data);
  assert(parsed.name, "Nombre requerido.");

  if (parsed.calculationType === "PERCENTAGE" || parsed.calculationType === "PERCENTAGE_PLUS_FIXED") {
    assert(parsed.rate !== null, "Se requiere una tasa porcentual.");
  }
  if (parsed.calculationType === "FIXED_AMOUNT" || parsed.calculationType === "PERCENTAGE_PLUS_FIXED") {
    assert(parsed.fixedAmount !== null, "Se requiere un monto fijo.");
  }

  const isActive = data?.isActive === false ? false : true;
  const code = parsed.code || s(data?.code);

  return prisma.tax.update({
    where: { id },
    data: { ...parsed, code, isActive },
    select: SELECT,
  });
}

export async function cloneTax(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const original = await prisma.tax.findFirst({ where: { id, jewelryId, deletedAt: null }, select: SELECT });
  assert(original, "Impuesto no encontrado.");

  const newName = `${original.name} (copia)`;
  const newCode = await generateTaxCode(jewelryId, newName);

  return prisma.tax.create({
    data: {
      jewelryId,
      name: newName,
      code: newCode,
      taxType: original.taxType,
      calculationType: original.calculationType,
      rate: original.rate,
      fixedAmount: original.fixedAmount,
      applyOn: original.applyOn,
      includedInPrice: original.includedInPrice,
      validFrom: original.validFrom,
      validTo: original.validTo,
      sortOrder: original.sortOrder,
      notes: original.notes,
      isActive: false, // clones start inactive
    },
    select: SELECT,
  });
}

export async function toggleTax(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");
  const tax = await prisma.tax.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true, isActive: true } });
  assert(tax, "Impuesto no encontrado.");
  return prisma.tax.update({ where: { id }, data: { isActive: !tax.isActive }, select: SELECT });
}

export async function deleteTax(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");
  const tax = await prisma.tax.findFirst({ where: { id, jewelryId, deletedAt: null }, select: { id: true } });
  assert(tax, "Impuesto no encontrado.");
  return prisma.tax.update({ where: { id }, data: { deletedAt: new Date(), isActive: false }, select: { id: true } });
}

async function generateTaxCode(jewelryId: string, name: string): Promise<string> {
  const prefix = name
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-zA-Z0-9]/g, "").toUpperCase().substring(0, 6).padEnd(3, "X");
  const count = await prisma.tax.count({ where: { jewelryId } });
  return `${prefix}${String(count + 1).padStart(2, "0")}`;
}
