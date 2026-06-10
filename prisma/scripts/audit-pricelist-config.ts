// prisma/scripts/audit-pricelist-config.ts
// =============================================================================
// AUDITORÍA — SOLO LECTURA. No escribe nada. Imprime la config real de las
// listas de precios desde la base de datos.
//   Uso: npx tsx prisma/scripts/audit-pricelist-config.ts
// =============================================================================
import { prisma } from "../../src/lib/prisma.js";

async function main() {
  // Columnas REALES del modelo PriceList (marginCalculationMode / breakdownMode
  // NO existen en el schema — se reporta explícitamente abajo).
  const lists = await prisma.priceList.findMany({
    where:  { deletedAt: null },
    orderBy: [{ name: "asc" }],
    select: {
      id:                            true,
      name:                          true,
      mode:                          true,   // PriceListMode (MARGIN_TOTAL | METAL_HECHURA | COST_PER_GRAM)
      roundingTarget:                true,
      roundingMode:                  true,
      roundingDirection:             true,
      roundingApplyOn:               true,
      roundingModeHechura:           true,
      roundingDirectionHechura:      true,
      commercialRoundingScope:       true,
      commercialRoundingMetalDomain: true,
      balanceMode:                   true,   // lo más cercano a "breakdownMode"
      marginTotal:                   true,
      marginMetal:                   true,
      marginHechura:                 true,
      isActive:                      true,
    },
  });

  // eslint-disable-next-line no-console
  console.log(`\n>>> Listas de precios encontradas: ${lists.length}\n`);
  for (const l of lists) {
    const tratadaComo =
      l.mode === "METAL_HECHURA" && l.roundingTarget === "METAL"
        ? "METAL_HECHURA (BREAKDOWN comercial)"
        : "MARGIN_TOTAL / UNIFIED comercial";
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({
      id:                            l.id,
      name:                          l.name,
      mode:                          l.mode,
      roundingTarget:                l.roundingTarget,
      roundingMode:                  l.roundingMode,
      roundingDirection:             l.roundingDirection,
      roundingApplyOn:               l.roundingApplyOn,
      roundingModeHechura:           l.roundingModeHechura,
      roundingDirectionHechura:      l.roundingDirectionHechura,
      commercialRoundingScope:       l.commercialRoundingScope,
      commercialRoundingMetalDomain: l.commercialRoundingMetalDomain,
      balanceMode:                   l.balanceMode,
      marginTotal:                   l.marginTotal?.toString() ?? null,
      marginMetal:                   l.marginMetal?.toString() ?? null,
      marginHechura:                 l.marginHechura?.toString() ?? null,
      isActive:                      l.isActive,
      __motor_la_trata_como__:       tratadaComo,
    }, null, 2));
  }
  // eslint-disable-next-line no-console
  console.log(`\n>>> NOTA: las columnas 'marginCalculationMode' y 'breakdownMode' NO existen en el modelo PriceList.\n`);
}

main()
  .then(() => process.exit(0))
  .catch((e) => { console.error(e); process.exit(1); });
