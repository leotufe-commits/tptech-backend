import { prisma } from "../../lib/prisma.js";
import type { CommissionBase, CommissionType } from "@prisma/client";

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

const VALID_COMMISSION: CommissionType[] = ["NONE", "PERCENTAGE", "FIXED_AMOUNT"];
const VALID_COMMISSION_BASE: CommissionBase[] = ["GROSS", "NET", "MARGIN"];

const SELLER_SELECT = {
  id: true,
  jewelryId: true,
  firstName: true,
  lastName: true,
  displayName: true,
  documentType: true,
  documentNumber: true,
  email: true,
  phone: true,
  avatarUrl: true,
  street: true,
  streetNumber: true,
  city: true,
  province: true,
  country: true,
  postalCode: true,
  commissionType: true,
  commissionValue: true,
  commissionBase: true,
  userId: true,
  isFavorite: true,
  isActive: true,
  sortOrder: true,
  notes: true,
  deletedAt: true,
  createdAt: true,
  updatedAt: true,
  warehouses: {
    select: {
      warehouseId: true,
      warehouse: { select: { id: true, name: true, isActive: true } },
    },
  },
  attachments: {
    where: { deletedAt: null },
    select: {
      id: true,
      filename: true,
      url: true,
      mimeType: true,
      size: true,
      createdAt: true,
    },
    orderBy: { createdAt: "asc" as const },
  },
} as const;

export async function listSellers(jewelryId: string) {
  assert(jewelryId, "Tenant inválido.");
  return prisma.seller.findMany({
    where: { jewelryId, deletedAt: null },
    select: SELLER_SELECT,
    orderBy: [{ isFavorite: "desc" }, { lastName: "asc" }, { firstName: "asc" }],
  });
}

export async function createSeller(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");

  const firstName = s(data?.firstName);
  const lastName = s(data?.lastName);
  assert(firstName, "Nombre requerido.");
  assert(lastName, "Apellido requerido.");

  const displayName = s(data?.displayName) || `${firstName} ${lastName}`;

  const commissionType: CommissionType = VALID_COMMISSION.includes(data?.commissionType)
    ? data.commissionType
    : "NONE";

  const commissionBase: CommissionBase = VALID_COMMISSION_BASE.includes(data?.commissionBase)
    ? data.commissionBase
    : "NET";

  const commissionValue =
    commissionType !== "NONE"
      ? String(parseFloat(String(data?.commissionValue ?? 0)) || 0)
      : null;

  if (commissionType !== "NONE") {
    assert(commissionValue !== null, "Valor de comisión requerido.");
  }

  const isFavorite = data?.isFavorite === true;
  const warehouseIds: string[] = Array.isArray(data?.warehouseIds)
    ? data.warehouseIds.map(s).filter(Boolean)
    : [];

  if (warehouseIds.length > 0) {
    const validWarehouses = await prisma.warehouse.findMany({
      where: { id: { in: warehouseIds }, jewelryId, deletedAt: null },
      select: { id: true },
    });
    assert(validWarehouses.length === warehouseIds.length, "Uno o más almacenes no son válidos.");
  }

  if (isFavorite) {
    await prisma.seller.updateMany({
      where: { jewelryId, deletedAt: null, isFavorite: true },
      data: { isFavorite: false },
    });
  }

  return prisma.seller.create({
    data: {
      jewelryId,
      firstName,
      lastName,
      displayName,
      documentType: s(data?.documentType),
      documentNumber: s(data?.documentNumber),
      email: s(data?.email),
      phone: s(data?.phone),
      avatarUrl: s(data?.avatarUrl),
      street: s(data?.street),
      streetNumber: s(data?.streetNumber),
      city: s(data?.city),
      province: s(data?.province),
      country: s(data?.country),
      postalCode: s(data?.postalCode),
      commissionType,
      commissionValue: commissionValue ?? undefined,
      commissionBase,
      userId: s(data?.userId) || null,
      isFavorite,
      isActive: true,
      sortOrder: Number(data?.sortOrder ?? 0) || 0,
      notes: s(data?.notes),
      warehouses:
        warehouseIds.length > 0
          ? { create: warehouseIds.map((wid) => ({ warehouseId: wid, jewelryId })) }
          : undefined,
    },
    select: SELLER_SELECT,
  });
}

export async function updateSeller(id: string, jewelryId: string, data: any) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const existing = await prisma.seller.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(existing, "Vendedor no encontrado.");

  const firstName = s(data?.firstName);
  const lastName = s(data?.lastName);
  assert(firstName, "Nombre requerido.");
  assert(lastName, "Apellido requerido.");

  const displayName = s(data?.displayName) || `${firstName} ${lastName}`;

  const commissionType: CommissionType = VALID_COMMISSION.includes(data?.commissionType)
    ? data.commissionType
    : "NONE";

  const commissionBase: CommissionBase = VALID_COMMISSION_BASE.includes(data?.commissionBase)
    ? data.commissionBase
    : "NET";

  const commissionValue =
    commissionType !== "NONE"
      ? String(parseFloat(String(data?.commissionValue ?? 0)) || 0)
      : null;

  const isFavorite = data?.isFavorite === true;
  const isActive = data?.isActive === false ? false : true;

  const warehouseIds: string[] = Array.isArray(data?.warehouseIds)
    ? data.warehouseIds.map(s).filter(Boolean)
    : [];

  if (warehouseIds.length > 0) {
    const validWarehouses = await prisma.warehouse.findMany({
      where: { id: { in: warehouseIds }, jewelryId, deletedAt: null },
      select: { id: true },
    });
    assert(validWarehouses.length === warehouseIds.length, "Uno o más almacenes no son válidos.");
  }

  if (isFavorite) {
    await prisma.seller.updateMany({
      where: { jewelryId, deletedAt: null, isFavorite: true, id: { not: id } },
      data: { isFavorite: false },
    });
  }

  await prisma.sellerWarehouse.deleteMany({ where: { sellerId: id } });

  return prisma.seller.update({
    where: { id },
    data: {
      firstName,
      lastName,
      displayName,
      documentType: s(data?.documentType),
      documentNumber: s(data?.documentNumber),
      email: s(data?.email),
      phone: s(data?.phone),
      street: s(data?.street),
      streetNumber: s(data?.streetNumber),
      city: s(data?.city),
      province: s(data?.province),
      country: s(data?.country),
      postalCode: s(data?.postalCode),
      commissionType,
      commissionValue: commissionValue ?? undefined,
      commissionBase,
      isFavorite,
      isActive,
      sortOrder: Number(data?.sortOrder ?? 0) || 0,
      notes: s(data?.notes),
      warehouses:
        warehouseIds.length > 0
          ? { create: warehouseIds.map((wid) => ({ warehouseId: wid, jewelryId })) }
          : undefined,
    },
    select: SELLER_SELECT,
  });
}

export async function updateSellerAvatar(id: string, jewelryId: string, avatarUrl: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const seller = await prisma.seller.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(seller, "Vendedor no encontrado.");

  return prisma.seller.update({
    where: { id },
    data: { avatarUrl },
    select: SELLER_SELECT,
  });
}

export async function toggleSeller(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const s2 = await prisma.seller.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, isActive: true },
  });
  assert(s2, "Vendedor no encontrado.");

  return prisma.seller.update({
    where: { id },
    data: { isActive: !s2.isActive },
    select: SELLER_SELECT,
  });
}

export async function setFavoriteSeller(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const s2 = await prisma.seller.findFirst({
    where: { id, jewelryId, deletedAt: null, isActive: true },
    select: { id: true },
  });
  assert(s2, "Vendedor no encontrado o inactivo.");

  await prisma.seller.updateMany({
    where: { jewelryId, deletedAt: null },
    data: { isFavorite: false },
  });

  return prisma.seller.update({
    where: { id },
    data: { isFavorite: true },
    select: SELLER_SELECT,
  });
}

export async function deleteSeller(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const s2 = await prisma.seller.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(s2, "Vendedor no encontrado.");

  return prisma.seller.update({
    where: { id },
    data: { deletedAt: new Date(), isActive: false },
    select: { id: true },
  });
}

export async function addSellerAttachment(
  id: string,
  jewelryId: string,
  data: { filename: string; url: string; mimeType: string; size: number }
) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const seller = await prisma.seller.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(seller, "Vendedor no encontrado.");

  return prisma.sellerAttachment.create({
    data: {
      sellerId: id,
      jewelryId,
      filename: data.filename,
      url: data.url,
      mimeType: data.mimeType,
      size: data.size,
    },
    select: { id: true, filename: true, url: true, mimeType: true, size: true, createdAt: true },
  });
}

export async function deleteSellerAttachment(
  sellerId: string,
  attachmentId: string,
  jewelryId: string
) {
  assert(sellerId, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const att = await prisma.sellerAttachment.findFirst({
    where: { id: attachmentId, sellerId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(att, "Adjunto no encontrado.");

  return prisma.sellerAttachment.update({
    where: { id: attachmentId },
    data: { deletedAt: new Date() },
    select: { id: true },
  });
}