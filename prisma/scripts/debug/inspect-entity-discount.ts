/**
 * prisma/scripts/debug/inspect-entity-discount.ts
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Herramienta de diagnóstico — condición comercial de un cliente
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Para qué sirve:
 *   Inspecciona en DB la configuración comercial (descuento / bonificación /
 *   recargo) de uno o varios `CommercialEntity` y reporta cómo la va a
 *   aplicar el `pricing-engine`. En particular, indica si el ajuste se va a
 *   imputar al COMPONENTE (Metal/Hechura) o quedar a nivel TOTAL.
 *
 *   Campos consultados:
 *     - `commercialRuleType`   (DISCOUNT | BONUS | SURCHARGE | null)
 *     - `commercialValueType`  (PERCENTAGE | FIXED_AMOUNT)
 *     - `commercialValue`      (porcentaje o monto fijo)
 *     - `commercialApplyOn`    (TOTAL | METAL | HECHURA | METAL_Y_HECHURA |
 *                               PRODUCT | SERVICE | null)
 *
 * Cuándo usarlo:
 *   - Cuando un descuento de cliente "no aparece" en la composición Metal/
 *     Hechura del simulador o de la factura, pero sí se refleja en el total.
 *     → Casi siempre es porque `commercialApplyOn` está en `TOTAL` o `null`.
 *   - Para auditar todos los clientes con regla comercial activa antes de
 *     un cierre / migración (`--list`).
 *   - Para validar tras editar la condición comercial desde la UI que el
 *     dato persistido en DB es el esperado.
 *
 * Qué datos devuelve:
 *   Modo `<commercialEntityId>` (inspección puntual):
 *     JSON con id, jewelryId, displayName, entityType, commercialRuleType,
 *     commercialValueType, commercialValue, commercialApplyOn, y el bloque
 *     `diagnosticoMotor` con:
 *       - `seImputaAComponente: boolean` — true si el motor va a rolar el
 *         ajuste al componente Metal/Hechura.
 *       - `razonSiNoImputa: string | null` — explicación cuando no rola
 *         (typicamente `commercialApplyOn=null` o `=TOTAL`).
 *
 *   Modo `--list` (listado):
 *     Una línea por cliente con regla comercial activa, marcada con `✓`
 *     (se rola al componente) o `✗` (queda a nivel TOTAL).
 *
 * Usos:
 *   npm run debug:entity-discount -- <commercialEntityId>
 *   npm run debug:entity-discount -- --list
 *   npm run debug:entity-discount -- --list --jewelry <jewelryId>
 *
 *   (Equivalente directo: `tsx prisma/scripts/debug/inspect-entity-discount.ts ...`)
 *
 * Cómo corregir si `seImputaAComponente=false`:
 *   - Desde la UI: editar el cliente en Configuración del sistema → Entidades
 *     comerciales → seleccionar `METAL` o `HECHURA` en el campo "Aplicar a"
 *     de la condición comercial.
 *   - Directo en DB:
 *       UPDATE "CommercialEntity"
 *          SET "commercialApplyOn" = 'HECHURA'
 *        WHERE id = '<commercialEntityId>';
 */

import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma = new PrismaClient({ adapter });

async function inspectOne(entityId: string) {
  const e = await prisma.commercialEntity.findFirst({
    where: { id: entityId, deletedAt: null },
    select: {
      id:                  true,
      jewelryId:           true,
      displayName:         true,
      entityType:          true,
      commercialRuleType:  true,
      commercialValueType: true,
      commercialValue:     true,
      commercialApplyOn:   true,
    },
  });
  if (!e) {
    console.log(`✗ No se encontró CommercialEntity con id="${entityId}"`);
    return;
  }
  const willTrackComponent =
    (e.commercialRuleType === "DISCOUNT" || e.commercialRuleType === "BONUS" ||
     e.commercialRuleType === "SURCHARGE") &&
    e.commercialValue != null && parseFloat(e.commercialValue.toString()) > 0 &&
    (e.commercialApplyOn === "METAL" || e.commercialApplyOn === "HECHURA");

  console.log(JSON.stringify({
    id:                  e.id,
    jewelryId:           e.jewelryId,
    displayName:         e.displayName,
    entityType:          e.entityType,
    commercialRuleType:  e.commercialRuleType,
    commercialValueType: e.commercialValueType,
    commercialValue:     e.commercialValue?.toString() ?? null,
    commercialApplyOn:   e.commercialApplyOn,
    diagnosticoMotor: {
      seImputaAComponente: willTrackComponent,
      // Casos donde NO se imputa al componente (descuento se aplica pero
      // queda fuera de componentSaleBreakdown.hechura/metal):
      razonSiNoImputa: !willTrackComponent
        ? (e.commercialRuleType == null
            ? "Sin commercialRuleType — el motor no aplica ningún ajuste"
            : (e.commercialApplyOn == null || e.commercialApplyOn === "TOTAL"
                ? `commercialApplyOn=${e.commercialApplyOn ?? "null"} — el motor aplica al TOTAL, no al componente`
                : (e.commercialApplyOn === "METAL_Y_HECHURA" || e.commercialApplyOn === "PRODUCT" || e.commercialApplyOn === "SERVICE"
                    ? `commercialApplyOn=${e.commercialApplyOn} — el motor lo trata como ajuste global`
                    : "Sin valor o valor=0")))
        : null,
    },
  }, null, 2));
}

async function listCandidates(jewelryId?: string) {
  const rows = await prisma.commercialEntity.findMany({
    where: {
      deletedAt: null,
      commercialRuleType: { not: null },
      ...(jewelryId ? { jewelryId } : {}),
    },
    select: {
      id:                  true,
      jewelryId:           true,
      displayName:         true,
      entityType:          true,
      commercialRuleType:  true,
      commercialValueType: true,
      commercialValue:     true,
      commercialApplyOn:   true,
    },
    orderBy: [{ jewelryId: "asc" }, { displayName: "asc" }],
  });
  if (rows.length === 0) {
    console.log("No hay CommercialEntity con commercialRuleType seteado.");
    return;
  }
  console.log(`Encontrados ${rows.length} cliente(s) con regla comercial:\n`);
  for (const r of rows) {
    const flag = r.commercialApplyOn === "METAL" || r.commercialApplyOn === "HECHURA"
      ? "✓"
      : "✗";
    console.log(`${flag} id=${r.id}  tenant=${r.jewelryId}`);
    console.log(`   displayName=${r.displayName}`);
    console.log(`   ${r.commercialRuleType} ${r.commercialValueType} ${r.commercialValue?.toString() ?? "—"} applyOn=${r.commercialApplyOn ?? "null"}`);
    console.log("");
  }
  console.log("(✓ se rola al desglose por componente, ✗ se aplica al TOTAL y NO entra al card hechura)");
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--list")) {
    const jIdx = args.indexOf("--jewelry");
    const jewelryId = jIdx >= 0 ? args[jIdx + 1] : undefined;
    await listCandidates(jewelryId);
    return;
  }
  const id = args[0];
  if (!id) {
    console.log("Uso:");
    console.log("  npm run debug:entity-discount -- <commercialEntityId>");
    console.log("  npm run debug:entity-discount -- --list");
    console.log("  npm run debug:entity-discount -- --list --jewelry <jewelryId>");
    process.exit(1);
  }
  await inspectOne(id);
}

main()
  .catch((e) => { console.error(e); process.exit(1); })
  .finally(async () => { await prisma.$disconnect(); });
