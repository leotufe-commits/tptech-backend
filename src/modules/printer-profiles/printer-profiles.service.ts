// src/modules/printer-profiles/printer-profiles.service.ts
import { prisma } from "../../lib/prisma.js";

function assert(cond: any, msg: string, status = 400) {
  if (!cond) { const e: any = new Error(msg); e.status = status; throw e; }
}

const PP_SELECT = {
  id: true, name: true, type: true, dpi: true,
  pageWidthMm: true, pageHeightMm: true,
  marginTopMm: true, marginLeftMm: true, marginRightMm: true, marginBottomMm: true,
  gapHMm: true, gapVMm: true, columns: true,
  isDefault: true, isActive: true, deletedAt: true, createdAt: true, updatedAt: true,
} as const;

export async function listPrinterProfiles(jewelryId: string) {
  return prisma.printerProfile.findMany({
    where: { jewelryId, deletedAt: null },
    select: PP_SELECT,
    orderBy: [{ isDefault: "desc" }, { name: "asc" }],
  });
}

export async function createPrinterProfile(jewelryId: string, data: any) {
  assert(data.name?.trim(), "El nombre es requerido.");

  if (data.isDefault) {
    await prisma.printerProfile.updateMany({
      where: { jewelryId, deletedAt: null, isDefault: true },
      data: { isDefault: false },
    });
  }

  return prisma.printerProfile.create({
    data: {
      jewelryId,
      name:           data.name.trim(),
      type:           data.type ?? "THERMAL",
      dpi:            Number(data.dpi ?? 203),
      pageWidthMm:    Number(data.pageWidthMm ?? 210),
      pageHeightMm:   Number(data.pageHeightMm ?? 297),
      marginTopMm:    Number(data.marginTopMm ?? 5),
      marginLeftMm:   Number(data.marginLeftMm ?? 5),
      marginRightMm:  Number(data.marginRightMm ?? 5),
      marginBottomMm: Number(data.marginBottomMm ?? 5),
      gapHMm:         Number(data.gapHMm ?? 2),
      gapVMm:         Number(data.gapVMm ?? 2),
      columns:        Number(data.columns ?? 1),
      isDefault:      !!data.isDefault,
      isActive:       data.isActive !== false,
    },
    select: PP_SELECT,
  });
}

export async function updatePrinterProfile(id: string, jewelryId: string, data: any) {
  const existing = await prisma.printerProfile.findFirst({ where: { id, jewelryId, deletedAt: null } });
  assert(existing, "Perfil no encontrado.", 404);

  if (data.isDefault === true) {
    await prisma.printerProfile.updateMany({
      where: { jewelryId, deletedAt: null, isDefault: true, id: { not: id } },
      data: { isDefault: false },
    });
  }

  return prisma.printerProfile.update({
    where: { id },
    data: {
      ...(data.name           !== undefined ? { name:           data.name.trim() }           : {}),
      ...(data.type           !== undefined ? { type:           data.type }                  : {}),
      ...(data.dpi            !== undefined ? { dpi:            Number(data.dpi) }           : {}),
      ...(data.pageWidthMm    !== undefined ? { pageWidthMm:    Number(data.pageWidthMm) }   : {}),
      ...(data.pageHeightMm   !== undefined ? { pageHeightMm:   Number(data.pageHeightMm) }  : {}),
      ...(data.marginTopMm    !== undefined ? { marginTopMm:    Number(data.marginTopMm) }   : {}),
      ...(data.marginLeftMm   !== undefined ? { marginLeftMm:   Number(data.marginLeftMm) }  : {}),
      ...(data.marginRightMm  !== undefined ? { marginRightMm:  Number(data.marginRightMm) } : {}),
      ...(data.marginBottomMm !== undefined ? { marginBottomMm: Number(data.marginBottomMm) }: {}),
      ...(data.gapHMm         !== undefined ? { gapHMm:         Number(data.gapHMm) }        : {}),
      ...(data.gapVMm         !== undefined ? { gapVMm:         Number(data.gapVMm) }        : {}),
      ...(data.columns        !== undefined ? { columns:        Number(data.columns) }        : {}),
      ...(data.isDefault      !== undefined ? { isDefault:      !!data.isDefault }            : {}),
      ...(data.isActive       !== undefined ? { isActive:       !!data.isActive }             : {}),
    },
    select: PP_SELECT,
  });
}

export async function deletePrinterProfile(id: string, jewelryId: string) {
  const existing = await prisma.printerProfile.findFirst({ where: { id, jewelryId, deletedAt: null } });
  assert(existing, "Perfil no encontrado.", 404);
  await prisma.printerProfile.update({ where: { id }, data: { deletedAt: new Date(), isActive: false } });
}
