/**
 * prisma/scripts/create-warning-fixture.ts
 *
 * Fixture visual para validar LOW_MARGIN / WARNING puro.
 * Debe permanecer sin metal ni costos parciales.
 *
 * ¿Para qué sirve?
 *   El motor de pricing solo emite `LOW_MARGIN` cuando se cumplen TODAS estas
 *   condiciones simultáneamente:
 *     · `unitCost` numérico (no null),
 *     · `unitPrice > 0`,
 *     · `marginPercent >= 0 && marginPercent < pricingLowMarginWarningPercent`,
 *     · sin `COST_UNRESOLVED`, sin `PARTIAL_DATA`, sin LOSS_SALE/ZERO en
 *       `policy.blockingAlerts` activos.
 *
 *   Artículos sin `ArticleCostLine` caen a `COST_UNRESOLVED + PARTIAL_DATA` →
 *   `RISK` (naranja). Artículos con metales sin cotización vigente caen a
 *   `PARTIAL_DATA` → `RISK`. Por eso un "WARNING puro" (ámbar) es difícil de
 *   reproducir manualmente — este fixture lo deja siempre disponible.
 *
 * Qué crea (idempotente):
 *   · 1 Article: code="PRUEBA-WARN", articleType=PRODUCT, status=ACTIVE,
 *     stockMode=BY_ARTICLE, sin metal, sin variantes.
 *   · 1 ArticleCostLine: type=PRODUCT, unitValue=1000, currencyId=null
 *     (= moneda base del tenant, según `schema.prisma` del modelo).
 *
 * Garantías:
 *   · No corre si NODE_ENV="production".
 *   · No crea duplicados: busca por (jewelryId, code) antes de crear.
 *   · No modifica artículos preexistentes con otro code/name.
 *   · No elimina ni desactiva nada.
 *   · Si el artículo ya tiene cualquier ArticleCostLine, no agrega la nuestra.
 *
 * Uso:
 *   tsx prisma/scripts/create-warning-fixture.ts
 *
 *   Si en DB hay más de una `Jewelry`, especificar cuál:
 *   FIXTURE_JEWELRY_ID=<id> tsx prisma/scripts/create-warning-fixture.ts
 *
 * Cómo reproducir el WARNING ámbar en Factura:
 *   1. En Factura de ventas, agregar el artículo "Prueba-WARN".
 *   2. Cantidad 1.
 *   3. Editar el precio manualmente a 1090.
 *   4. Sin bonificación, IVA 0% (o exento).
 *   5. Resultado: unitCost=1000, marginPercent≈9%, chip ámbar "MARGEN BAJO",
 *      caja ámbar visible, NO modal de confirmación reforzada.
 */

import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";

const FIXTURE_CODE = "PRUEBA-WARN";
const FIXTURE_NAME = "Prueba-WARN";
const FIXTURE_COST_VALUE = 1000;
const FIXTURE_NOTES =
  "Fixture visual para validar LOW_MARGIN / WARNING puro. " +
  "Debe permanecer sin metal ni costos parciales. " +
  "Creado por prisma/scripts/create-warning-fixture.ts.";

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma  = new PrismaClient({ adapter });

function abort(msg: string): never {
  console.error(`\n❌ ${msg}\n`);
  process.exit(1);
}

async function resolveJewelryId(): Promise<string> {
  const explicit = (process.env.FIXTURE_JEWELRY_ID ?? "").trim();
  if (explicit) {
    const j = await prisma.jewelry.findUnique({
      where:  { id: explicit },
      select: { id: true, name: true },
    });
    if (!j) abort(`FIXTURE_JEWELRY_ID="${explicit}" no existe en DB.`);
    console.log(`→ Tenant explícito (env FIXTURE_JEWELRY_ID): ${j!.name} (${j!.id})`);
    return j!.id;
  }

  const jewelries = await prisma.jewelry.findMany({
    select: { id: true, name: true },
    take:   5,
  });

  if (jewelries.length === 0) {
    abort("No hay ninguna Jewelry en DB. Inicializá un tenant antes de correr este script.");
  }

  if (jewelries.length > 1) {
    const list = jewelries.map((j) => `  - ${j.name} (${j.id})`).join("\n");
    abort(
      "Hay más de una Jewelry en DB. Elegí cuál usar con:\n\n" +
      `  FIXTURE_JEWELRY_ID=<id> tsx prisma/scripts/create-warning-fixture.ts\n\n` +
      "Tenants disponibles:\n" + list,
    );
  }

  console.log(`→ Tenant detectado (único en DB): ${jewelries[0].name} (${jewelries[0].id})`);
  return jewelries[0].id;
}

async function main() {
  console.log("=".repeat(60));
  console.log("Fixture: Prueba-WARN (LOW_MARGIN puro / WARNING ámbar)");
  console.log("=".repeat(60));

  // Guard estricto: nunca tocar producción.
  if ((process.env.NODE_ENV ?? "").toLowerCase() === "production") {
    abort(
      "NODE_ENV=production detectado. Este fixture es solo para desarrollo. " +
      "Para forzar igualmente: editá el script y remové el guard a mano.",
    );
  }

  const jewelryId = await resolveJewelryId();

  // 1) Artículo: buscar por (jewelryId, code) — idempotencia primaria.
  let article = await prisma.article.findFirst({
    where:  { jewelryId, code: FIXTURE_CODE },
    select: {
      id: true, name: true, articleType: true, status: true, stockMode: true,
    },
  });

  if (!article) {
    article = await prisma.article.create({
      data: {
        jewelryId,
        code:        FIXTURE_CODE,
        name:        FIXTURE_NAME,
        description: "Artículo de prueba — fixture WARNING ámbar.",
        articleType: "PRODUCT",
        status:      "ACTIVE",
        stockMode:   "BY_ARTICLE",
        // Sin metal, sin merma, sin variantes activas. Precio manual lo
        // ingresa el operador en Factura (no fijamos `salePrice` para que
        // la receta sea explícita y reproducible: precio 1090 → margen 9%).
        notes:       FIXTURE_NOTES,
        isActive:    true,
      },
      select: {
        id: true, name: true, articleType: true, status: true, stockMode: true,
      },
    });
    console.log(`✓ Article creado: ${article.name} (${article.id})`);
  } else {
    console.log(`= Article ya existía: ${article.name} (${article.id}). No se modifica.`);
  }

  // 2) ArticleCostLine: si el artículo ya tiene cualquier cost line, no
  //    sumamos otra (idempotencia secundaria). Si está vacío, agregamos la
  //    nuestra: PRODUCT, unitValue=1000, moneda base del tenant.
  const existingCount = await prisma.articleCostLine.count({
    where: { articleId: article.id },
  });

  if (existingCount > 0) {
    console.log(
      `= Article ya tenía ${existingCount} ArticleCostLine — no se agrega ` +
      "ninguna otra (idempotente). Si la cost line preexistente no es la del " +
      "fixture (PRODUCT $1000 base), el WARNING puede no reproducirse — " +
      "revisar manualmente.",
    );
  } else {
    const cost = await prisma.articleCostLine.create({
      data: {
        articleId:    article.id,
        jewelryId,
        type:         "PRODUCT",
        label:        "Costo fijo (fixture WARNING)",
        quantity:     1,
        unitValue:    FIXTURE_COST_VALUE,
        currencyId:   null,      // null = moneda base del tenant
        sortOrder:    0,
        affectsStock: false,     // no descuenta stock al confirmar venta
      },
      select: { id: true, unitValue: true },
    });
    console.log(`✓ ArticleCostLine creada: PRODUCT $${cost.unitValue} (${cost.id})`);
  }

  console.log("\n" + "─".repeat(60));
  console.log("✅ Fixture listo.");
  console.log("─".repeat(60));
  console.log(`Article ID: ${article.id}`);
  console.log(`Code:       ${FIXTURE_CODE}`);
  console.log(`Name:       ${FIXTURE_NAME}`);
  console.log("");
  console.log("Receta para ver WARNING ámbar en Factura:");
  console.log("  1) Crear una factura nueva.");
  console.log(`  2) Agregar el artículo "${FIXTURE_NAME}".`);
  console.log("  3) Cantidad: 1.");
  console.log("  4) Precio manual: 1090.");
  console.log("  5) Sin bonificación. IVA 0% (o cliente exento).");
  console.log("  → margen ≈ 9% < umbral recomendado (15%).");
  console.log("  → chip ÁMBAR 'MARGEN BAJO', caja ámbar visible.");
  console.log("  → NO se abre el modal de confirmación reforzada.");
}

main()
  .catch((err) => {
    console.error("\n❌ Error inesperado:\n", err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
