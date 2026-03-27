// commercial-entities.export.service.ts
// Exportación de entidades comerciales a CSV y XLSX.
import { prisma } from "../../lib/prisma.js";
import * as XLSX from "xlsx";

// ─── Tipos ───────────────────────────────────────────────────────────────────

export type ExportType   = "clients" | "suppliers";
export type ExportFormat = "csv" | "xlsx";

// ─── Columnas exportadas (label visible → campo de la fila plana) ─────────────

const EXPORT_HEADERS = [
  "Código",
  "Tipo entidad",
  "Razón social",
  "Nombre de fantasía",
  "Nombre",
  "Apellido",
  "Nombre visible",
  "Email principal",
  "Teléfono principal",
  "Tipo documento",
  "Número documento",
  "Condición IVA",
  "Término de pago",
  "Moneda habitual",
  "Lista de precios",
  "Límite crédito cliente",
  "Activo",
  "Origen",
  "Observaciones",
  // Dirección principal
  "Etiqueta dirección",
  "Calle",
  "Número",
  "Piso",
  "Depto",
  "Ciudad",
  "Provincia",
  "País",
  "Código postal",
  // Contacto principal
  "Nombre contacto",
  "Apellido contacto",
  "Cargo contacto",
  "Email contacto",
  "Teléfono contacto",
  "Notas contacto",
] as const;

type ExportRow = Record<(typeof EXPORT_HEADERS)[number], string>;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function safe(v: any): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return "";
  return String(v).trim();
}

function decimal(v: any): string {
  if (v === null || v === undefined) return "";
  const n = typeof v === "object" && "toString" in v ? v.toString() : String(v);
  return n.replace(/\.?0+$/, ""); // quita ceros innecesarios al final
}

function isoDate(): string {
  return new Date().toISOString().slice(0, 10);
}

// ─── Query ───────────────────────────────────────────────────────────────────

async function getEntitiesForExport(tenantId: string, type: ExportType) {
  return prisma.commercialEntity.findMany({
    where: {
      jewelryId: tenantId,
      deletedAt: null,
      ...(type === "clients" ? { isClient: true } : { isSupplier: true }),
    },
    select: {
      code:               true,
      entityType:         true,
      companyName:        true,
      tradeName:          true,
      firstName:          true,
      lastName:           true,
      displayName:        true,
      email:              true,
      phone:              true,
      documentType:       true,
      documentNumber:     true,
      ivaCondition:       true,
      paymentTerm:        true,
      creditLimitClient:  true,
      isActive:           true,
      sourceType:         true,
      notes:              true,
      currency:  { select: { code: true } },
      priceList: { select: { name: true } },
      addresses: {
        where:   { deletedAt: null },
        select:  { label: true, street: true, streetNumber: true, floor: true, apartment: true, city: true, province: true, country: true, postalCode: true, isDefault: true },
        orderBy: [{ isDefault: "desc" }, { createdAt: "asc" }],
        take: 1,
      },
      contacts: {
        where:   { deletedAt: null },
        select:  { firstName: true, lastName: true, position: true, email: true, phone: true, notes: true, isPrimary: true },
        orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
        take: 1,
      },
    },
    orderBy: { displayName: "asc" },
  });
}

// ─── Map → fila plana ─────────────────────────────────────────────────────────

type EntityData = Awaited<ReturnType<typeof getEntitiesForExport>>[number];

function mapEntityToRow(e: EntityData): ExportRow {
  const addr = e.addresses[0];
  const cont = e.contacts[0];

  return {
    "Código":               safe(e.code),
    "Tipo entidad":         e.entityType === "COMPANY" ? "EMPRESA" : "PERSONA",
    "Razón social":         safe(e.companyName),
    "Nombre de fantasía":   safe(e.tradeName),
    "Nombre":               safe(e.firstName),
    "Apellido":             safe(e.lastName),
    "Nombre visible":       safe(e.displayName),
    "Email principal":      safe(e.email),
    "Teléfono principal":   safe(e.phone),
    "Tipo documento":       safe(e.documentType),
    "Número documento":     safe(e.documentNumber),
    "Condición IVA":        safe(e.ivaCondition),
    "Término de pago":      safe(e.paymentTerm),
    "Moneda habitual":      safe(e.currency?.code),
    "Lista de precios":     safe(e.priceList?.name),
    "Límite crédito cliente":   decimal(e.creditLimitClient),
    "Activo":               e.isActive ? "Sí" : "No",
    "Origen":               safe(e.sourceType),
    "Observaciones":        safe(e.notes),
    // Dirección
    "Etiqueta dirección":   addr ? safe(addr.label)        : "",
    "Calle":                addr ? safe(addr.street)       : "",
    "Número":               addr ? safe(addr.streetNumber) : "",
    "Piso":                 addr ? safe(addr.floor)        : "",
    "Depto":                addr ? safe(addr.apartment)    : "",
    "Ciudad":               addr ? safe(addr.city)         : "",
    "Provincia":            addr ? safe(addr.province)     : "",
    "País":                 addr ? safe(addr.country)      : "",
    "Código postal":        addr ? safe(addr.postalCode)   : "",
    // Contacto
    "Nombre contacto":      cont ? safe(cont.firstName) : "",
    "Apellido contacto":    cont ? safe(cont.lastName)  : "",
    "Cargo contacto":       cont ? safe(cont.position)  : "",
    "Email contacto":       cont ? safe(cont.email)     : "",
    "Teléfono contacto":    cont ? safe(cont.phone)     : "",
    "Notas contacto":       cont ? safe(cont.notes)     : "",
  };
}

// ─── CSV ─────────────────────────────────────────────────────────────────────

function escapeCell(v: string): string {
  // Si contiene ;  "  salto de línea → envolver en comillas y escapar internas
  if (/[;"'\n\r]/.test(v)) return `"${v.replace(/"/g, '""')}"`;
  return v;
}

function buildCsv(rows: ExportRow[]): Buffer {
  const sep = ";";
  const lines: string[] = [EXPORT_HEADERS.map(escapeCell).join(sep)];
  for (const row of rows) {
    lines.push(EXPORT_HEADERS.map((h) => escapeCell(row[h])).join(sep));
  }
  const content = lines.join("\r\n");
  // BOM UTF-8 para compatibilidad con Excel en Argentina
  return Buffer.concat([Buffer.from("\uFEFF", "utf8"), Buffer.from(content, "utf8")]);
}

// ─── XLSX ────────────────────────────────────────────────────────────────────

function buildXlsx(rows: ExportRow[], sheetName: string): Buffer {
  const data = [
    EXPORT_HEADERS as unknown as string[],
    ...rows.map((row) => EXPORT_HEADERS.map((h) => row[h])),
  ];

  const ws = XLSX.utils.aoa_to_sheet(data);

  // Anchos de columna automáticos (basados en el header + valor más largo)
  ws["!cols"] = EXPORT_HEADERS.map((h) => {
    const maxContent = rows.reduce((max, r) => Math.max(max, r[h].length), h.length);
    return { wch: Math.min(maxContent + 2, 40) };
  });

  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, sheetName);

  return XLSX.write(wb, { type: "buffer", bookType: "xlsx" }) as Buffer;
}

// ─── Punto de entrada principal ───────────────────────────────────────────────

export async function exportEntities(
  tenantId: string,
  type: ExportType,
  format: ExportFormat,
): Promise<{ buffer: Buffer; filename: string; contentType: string }> {
  const entities  = await getEntitiesForExport(tenantId, type);
  const exportRows = entities.map(mapEntityToRow);

  const dateStr   = isoDate();
  const baseName  = type === "clients" ? "clientes" : "proveedores";
  const sheetName = type === "clients" ? "Clientes"  : "Proveedores";

  if (format === "csv") {
    return {
      buffer:      buildCsv(exportRows),
      filename:    `${baseName}-${dateStr}.csv`,
      contentType: "text/csv; charset=utf-8",
    };
  }

  return {
    buffer:      buildXlsx(exportRows, sheetName),
    filename:    `${baseName}-${dateStr}.xlsx`,
    contentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  };
}
