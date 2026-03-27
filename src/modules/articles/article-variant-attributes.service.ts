import { prisma } from "../../lib/prisma.js";

function s(v: any): string { return String(v ?? "").trim(); }
function assert(cond: any, msg: string, status = 400): void {
  if (!cond) { const e: any = new Error(msg); e.status = status; throw e; }
}

// ===========================================================================
// Helpers
// ===========================================================================

async function assertVariantAccess(variantId: string, articleId: string, jewelryId: string) {
  const v = await prisma.articleVariant.findFirst({
    where: { id: variantId, articleId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(v, "Variante no encontrada.", 404);
}

// ===========================================================================
// GET — devuelve los valores de atributos de variante con assignment+definition
// ===========================================================================
export async function getVariantAttributeValues(
  articleId: string,
  variantId: string,
  jewelryId: string,
) {
  await assertVariantAccess(variantId, articleId, jewelryId);

  return prisma.articleVariantAttributeValue.findMany({
    where: { variantId },
    select: {
      id: true,
      assignmentId: true,
      value: true,
      assignment: {
        select: {
          id: true,
          isRequired: true,
          sortOrder: true,
          isVariantAxis: true,
          definition: {
            select: {
              id: true,
              name: true,
              code: true,
              inputType: true,
              options: { select: { id: true, label: true, value: true } },
            },
          },
        },
      },
    },
    orderBy: { assignment: { sortOrder: "asc" as const } },
  });
}

// ===========================================================================
// PUT — upsert atómico de todos los valores de atributos de variante
// Valida:
//  1. assignmentId apunta a un ArticleCategoryAttribute con isVariantAxis=true
//  2. Valor compatible con inputType del definition
// ===========================================================================
export async function setVariantAttributeValues(
  articleId: string,
  variantId: string,
  jewelryId: string,
  values: { assignmentId: string; value: string }[],
) {
  await assertVariantAccess(variantId, articleId, jewelryId);
  assert(Array.isArray(values), "values debe ser un array.");

  if (values.length === 0) {
    // Nada que guardar; devolver estado actual
    return getVariantAttributeValues(articleId, variantId, jewelryId);
  }

  // Cargar todos los assignments referenciados en una sola query
  const assignmentIds = [...new Set(values.map(v => s(v.assignmentId)).filter(Boolean))];
  const assignments = await prisma.articleCategoryAttribute.findMany({
    where: { id: { in: assignmentIds }, jewelryId },
    select: {
      id: true,
      isVariantAxis: true,
      definition: {
        select: {
          inputType: true,
          options: { select: { value: true } },
        },
      },
    },
  });

  const assignmentMap = new Map(assignments.map(a => [a.id, a]));

  // Validar cada valor
  for (const { assignmentId, value } of values) {
    const raw = s(assignmentId);
    assert(raw, "assignmentId es obligatorio en cada elemento.");

    const assignment = assignmentMap.get(raw);
    assert(assignment, `El atributo "${raw}" no existe o no pertenece a este tenant.`);
    const asgn = assignment!;
    assert(
      asgn.isVariantAxis,
      `El atributo "${raw}" no está marcado como eje de variante (isVariantAxis=true). Solo se pueden asignar atributos de variante a variantes.`,
    );

    // Validación por inputType
    const inputType = asgn.definition?.inputType;
    const v = s(value);

    if (inputType === "NUMBER" || inputType === "DECIMAL") {
      assert(v === "" || !isNaN(Number(v)), `El valor "${v}" no es un número válido para el atributo "${raw}".`);
    }

    if (inputType === "BOOLEAN") {
      assert(v === "" || v === "true" || v === "false", `El valor para el atributo "${raw}" debe ser "true" o "false".`);
    }

    if (inputType === "SELECT") {
      const opts = asgn.definition?.options?.map(o => o.value) ?? [];
      assert(v === "" || opts.includes(v), `El valor "${v}" no es una opción válida para el atributo "${raw}".`);
    }

    if (inputType === "MULTISELECT") {
      if (v !== "") {
        const opts = new Set(asgn.definition?.options?.map(o => o.value) ?? []);
        const selected = v.split(",").map(x => x.trim());
        for (const sel of selected) {
          assert(opts.has(sel), `El valor "${sel}" no es una opción válida para el atributo "${raw}".`);
        }
      }
    }
  }

  // ── Verificar que no exista otra variante del mismo artículo con la misma
  //    combinación de ejes de variante (isVariantAxis=true).
  //    Esto evita duplicados como Color=Rojo+Talle=M repetido en dos variantes.
  const axisValues = values.filter(v => assignmentMap.get(s(v.assignmentId))?.isVariantAxis);
  if (axisValues.length > 0) {
    const axisAssIds = axisValues.map(v => s(v.assignmentId)).sort();

    // Clave normalizada de la combinación propuesta
    const proposedKey = axisAssIds
      .map(id => `${id}:${s(values.find(v => s(v.assignmentId) === id)?.value ?? "").toLowerCase()}`)
      .join("|");

    // Cargar todas las demás variantes activas del artículo con sus valores de eje
    const otherVariants = await prisma.articleVariant.findMany({
      where: { articleId, deletedAt: null, id: { not: variantId } },
      select: {
        code: true,
        attributeValues: {
          where: { assignmentId: { in: axisAssIds } },
          select: { assignmentId: true, value: true },
        },
      },
    });

    for (const ov of otherVariants) {
      const existingKey = axisAssIds
        .map(id => `${id}:${(ov.attributeValues.find(av => av.assignmentId === id)?.value ?? "").toLowerCase()}`)
        .join("|");
      if (existingKey === proposedKey) {
        const err: any = new Error(
          `Ya existe la variante "${ov.code}" con esa combinación de atributos. No se permiten combinaciones duplicadas.`
        );
        err.status = 409;
        throw err;
      }
    }
  }

  // Upsert atómico
  await prisma.$transaction(
    values.map(({ assignmentId, value }) =>
      prisma.articleVariantAttributeValue.upsert({
        where: { variantId_assignmentId: { variantId, assignmentId: s(assignmentId) } },
        create: { variantId, jewelryId, assignmentId: s(assignmentId), value: s(value) },
        update: { value: s(value) },
      })
    )
  );

  return getVariantAttributeValues(articleId, variantId, jewelryId);
}
