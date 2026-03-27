/**
 * prisma/fix-phone-prefixes.ts
 *
 * Migración de datos: normaliza todos los CatalogItem tipo PHONE_PREFIX al
 * formato "[ISO] +[CODIGO]" en todos los tenants.
 *
 * Ejecución:
 *   npx tsx prisma/fix-phone-prefixes.ts
 *
 * Idempotente: se puede ejecutar varias veces sin riesgo.
 * Usa transacción por jewelryId para garantizar integridad.
 */

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

// Mapa de código viejo → label nuevo (ISO + código)
const PREFIX_MAP: Record<string, string> = {
  "+54":  "AR +54",
  "+598": "UY +598",
  "+56":  "CL +56",
  "+55":  "BR +55",
  "+595": "PY +595",
  "+591": "BO +591",
  "+51":  "PE +51",
  "+1":   "US +1",
  "+34":  "ES +34",
  "+39":  "IT +39",
};

async function main() {
  console.log("🔧 Iniciando migración de prefijos telefónicos...\n");

  // Buscar todos los registros con formato viejo (label empieza con "+")
  const oldItems = await prisma.catalogItem.findMany({
    where: {
      type: "PHONE_PREFIX",
      label: { startsWith: "+" },
      deletedAt: null,
    },
    select: { id: true, jewelryId: true, label: true },
  });

  if (oldItems.length === 0) {
    console.log("✅ No hay prefijos en formato viejo. Nada que migrar.");
    return;
  }

  console.log(`📋 Encontrados ${oldItems.length} prefijos en formato viejo:\n`);
  for (const item of oldItems) {
    console.log(`  [${item.jewelryId}] "${item.label}" → "${PREFIX_MAP[item.label] ?? "SIN MAPEO"}"`);
  }
  console.log();

  // Agrupar por jewelryId para procesar cada tenant en su propia transacción
  const byTenant = new Map<string, typeof oldItems>();
  for (const item of oldItems) {
    const list = byTenant.get(item.jewelryId) ?? [];
    list.push(item);
    byTenant.set(item.jewelryId, list);
  }

  let totalUpdated = 0;
  let totalDeleted = 0;
  let totalSkipped = 0;

  for (const [jewelryId, items] of byTenant) {
    await prisma.$transaction(async (tx) => {
      for (const item of items) {
        const newLabel = PREFIX_MAP[item.label];

        if (!newLabel) {
          console.warn(`  ⚠️  Sin mapeo para "${item.label}" (jewelryId: ${jewelryId}) — omitido`);
          totalSkipped++;
          continue;
        }

        // Verificar si el nuevo label ya existe para este tenant
        const alreadyExists = await tx.catalogItem.findFirst({
          where: { jewelryId, type: "PHONE_PREFIX", label: newLabel, deletedAt: null },
          select: { id: true },
        });

        if (alreadyExists) {
          // El nuevo formato ya existe → eliminar el duplicado viejo (soft-delete)
          await tx.catalogItem.update({
            where: { id: item.id },
            data: { deletedAt: new Date() },
          });
          console.log(`  🗑️  [${jewelryId}] "${item.label}" → eliminado (ya existe "${newLabel}")`);
          totalDeleted++;
        } else {
          // No existe → renombrar al nuevo formato
          await tx.catalogItem.update({
            where: { id: item.id },
            data: { label: newLabel },
          });
          console.log(`  ✅  [${jewelryId}] "${item.label}" → "${newLabel}"`);
          totalUpdated++;
        }
      }
    });
  }

  console.log("\n📊 Resumen:");
  console.log(`  Actualizados: ${totalUpdated}`);
  console.log(`  Eliminados (duplicados): ${totalDeleted}`);
  console.log(`  Omitidos (sin mapeo): ${totalSkipped}`);
  console.log("\n✅ Migración completada.");
}

main()
  .catch((e) => {
    console.error("❌ Error en migración:", e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
