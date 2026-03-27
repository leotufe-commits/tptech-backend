// src/modules/label-templates/label-templates.service.ts
import { prisma } from "../../lib/prisma.js";

function assert(cond: any, msg: string, status = 400) {
  if (!cond) { const e: any = new Error(msg); e.status = status; throw e; }
}

const ELEMENT_SELECT = {
  id: true, type: true, label: true, fieldKey: true,
  x: true, y: true, width: true, height: true,
  fontSize: true, fontWeight: true, align: true,
  visible: true, sortOrder: true, configJson: true,
  createdAt: true,
} as const;

const TEMPLATE_SELECT = {
  id: true, name: true, widthMm: true, heightMm: true,
  dpi: true, orientation: true, bgColor: true,
  isDefault: true, isActive: true, deletedAt: true, createdAt: true, updatedAt: true,
  elements: { select: ELEMENT_SELECT, orderBy: { sortOrder: "asc" as const } },
} as const;

export async function listLabelTemplates(jewelryId: string) {
  return prisma.labelTemplate.findMany({
    where: { jewelryId, deletedAt: null },
    select: TEMPLATE_SELECT,
    orderBy: [{ isDefault: "desc" }, { name: "asc" }],
  });
}

export async function getLabelTemplate(id: string, jewelryId: string) {
  const t = await prisma.labelTemplate.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: TEMPLATE_SELECT,
  });
  assert(t, "Plantilla no encontrada.", 404);
  return t;
}

export async function createLabelTemplate(jewelryId: string, data: any) {
  assert(data.name?.trim(), "El nombre es requerido.");
  assert(Number(data.widthMm) > 0, "El ancho debe ser > 0.");
  assert(Number(data.heightMm) > 0, "El alto debe ser > 0.");

  if (data.isDefault) {
    await prisma.labelTemplate.updateMany({
      where: { jewelryId, deletedAt: null, isDefault: true },
      data: { isDefault: false },
    });
  }

  return prisma.labelTemplate.create({
    data: {
      jewelryId,
      name:        data.name.trim(),
      widthMm:     data.widthMm,
      heightMm:    data.heightMm,
      dpi:         Number(data.dpi ?? 203),
      orientation: data.orientation ?? "portrait",
      bgColor:     data.bgColor ?? "#ffffff",
      isDefault:   !!data.isDefault,
      isActive:    data.isActive !== false,
    },
    select: TEMPLATE_SELECT,
  });
}

export async function updateLabelTemplate(id: string, jewelryId: string, data: any) {
  const existing = await prisma.labelTemplate.findFirst({ where: { id, jewelryId, deletedAt: null } });
  assert(existing, "Plantilla no encontrada.", 404);

  if (data.isDefault === true) {
    await prisma.labelTemplate.updateMany({
      where: { jewelryId, deletedAt: null, isDefault: true, id: { not: id } },
      data: { isDefault: false },
    });
  }

  return prisma.labelTemplate.update({
    where: { id },
    data: {
      ...(data.name        !== undefined ? { name:        data.name.trim() }         : {}),
      ...(data.widthMm     !== undefined ? { widthMm:     data.widthMm }              : {}),
      ...(data.heightMm    !== undefined ? { heightMm:    data.heightMm }             : {}),
      ...(data.dpi         !== undefined ? { dpi:         Number(data.dpi) }          : {}),
      ...(data.orientation !== undefined ? { orientation: data.orientation }          : {}),
      ...(data.bgColor     !== undefined ? { bgColor:     data.bgColor }              : {}),
      ...(data.isDefault   !== undefined ? { isDefault:   !!data.isDefault }          : {}),
      ...(data.isActive    !== undefined ? { isActive:    !!data.isActive }            : {}),
    },
    select: TEMPLATE_SELECT,
  });
}

export async function deleteLabelTemplate(id: string, jewelryId: string) {
  const existing = await prisma.labelTemplate.findFirst({ where: { id, jewelryId, deletedAt: null } });
  assert(existing, "Plantilla no encontrada.", 404);
  await prisma.labelTemplate.update({ where: { id }, data: { deletedAt: new Date(), isActive: false } });
}

// ── Elements ────────────────────────────────────────────────────────────────

export async function addElement(templateId: string, jewelryId: string, data: any) {
  const template = await prisma.labelTemplate.findFirst({ where: { id: templateId, jewelryId, deletedAt: null } });
  assert(template, "Plantilla no encontrada.", 404);

  return prisma.labelElement.create({
    data: {
      templateId,
      type:       data.type ?? "TEXT",
      label:      data.label ?? "",
      fieldKey:   data.fieldKey ?? "",
      x:          Number(data.x ?? 2),
      y:          Number(data.y ?? 2),
      width:      Number(data.width ?? 20),
      height:     Number(data.height ?? 6),
      fontSize:   Number(data.fontSize ?? 8),
      fontWeight: data.fontWeight ?? "normal",
      align:      data.align ?? "left",
      visible:    data.visible !== false,
      sortOrder:  Number(data.sortOrder ?? 0),
      configJson: typeof data.configJson === "string" ? data.configJson : JSON.stringify(data.configJson ?? {}),
    },
    select: ELEMENT_SELECT,
  });
}

export async function updateElement(elementId: string, templateId: string, jewelryId: string, data: any) {
  const el = await prisma.labelElement.findFirst({
    where: { id: elementId, templateId, template: { jewelryId } },
  });
  assert(el, "Elemento no encontrado.", 404);

  return prisma.labelElement.update({
    where: { id: elementId },
    data: {
      ...(data.label      !== undefined ? { label:      data.label }                      : {}),
      ...(data.fieldKey   !== undefined ? { fieldKey:   data.fieldKey }                   : {}),
      ...(data.x          !== undefined ? { x:          Number(data.x) }                  : {}),
      ...(data.y          !== undefined ? { y:          Number(data.y) }                  : {}),
      ...(data.width      !== undefined ? { width:      Number(data.width) }              : {}),
      ...(data.height     !== undefined ? { height:     Number(data.height) }             : {}),
      ...(data.fontSize   !== undefined ? { fontSize:   Number(data.fontSize) }           : {}),
      ...(data.fontWeight !== undefined ? { fontWeight: data.fontWeight }                 : {}),
      ...(data.align      !== undefined ? { align:      data.align }                      : {}),
      ...(data.visible    !== undefined ? { visible:    !!data.visible }                  : {}),
      ...(data.sortOrder  !== undefined ? { sortOrder:  Number(data.sortOrder) }          : {}),
      ...(data.configJson !== undefined ? {
        configJson: typeof data.configJson === "string" ? data.configJson : JSON.stringify(data.configJson),
      } : {}),
    },
    select: ELEMENT_SELECT,
  });
}

export async function deleteElement(elementId: string, templateId: string, jewelryId: string) {
  const el = await prisma.labelElement.findFirst({
    where: { id: elementId, templateId, template: { jewelryId } },
  });
  assert(el, "Elemento no encontrado.", 404);
  await prisma.labelElement.delete({ where: { id: elementId } });
}

export async function replaceElements(templateId: string, jewelryId: string, elements: any[]) {
  const template = await prisma.labelTemplate.findFirst({ where: { id: templateId, jewelryId, deletedAt: null } });
  assert(template, "Plantilla no encontrada.", 404);

  await prisma.$transaction([
    prisma.labelElement.deleteMany({ where: { templateId } }),
    prisma.labelElement.createMany({
      data: elements.map((el, i) => ({
        templateId,
        type:       el.type ?? "TEXT",
        label:      el.label ?? "",
        fieldKey:   el.fieldKey ?? "",
        x:          Number(el.x ?? 0),
        y:          Number(el.y ?? 0),
        width:      Number(el.width ?? 20),
        height:     Number(el.height ?? 6),
        fontSize:   Number(el.fontSize ?? 8),
        fontWeight: el.fontWeight ?? "normal",
        align:      el.align ?? "left",
        visible:    el.visible !== false,
        sortOrder:  i,
        configJson: typeof el.configJson === "string" ? el.configJson : JSON.stringify(el.configJson ?? {}),
      })),
    }),
  ]);

  return prisma.labelTemplate.findFirst({
    where: { id: templateId },
    select: TEMPLATE_SELECT,
  });
}
