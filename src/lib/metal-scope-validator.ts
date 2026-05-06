// src/lib/metal-scope-validator.ts
//
// Validación del scope METALS para Promociones, Cupones y Descuentos por
// cantidad. Centraliza la regla: cuando el scope es METALS, la lista de
// `metalVariantIds` debe (a) tener al menos 1 elemento, (b) referenciar
// variantes que existen en el tenant, (c) estar activas, (d) no soft-deleted.
//
// Lanza errores con `status` HTTP poblado (mismo patrón que el resto del
// backend).
import { prisma } from "./prisma.js";

function err(msg: string, status = 400): never {
  const e: any = new Error(msg);
  e.status = status;
  throw e;
}

/**
 * Normaliza el input recibido del cliente y devuelve la lista de variantes
 * válidas. Si la lista contiene duplicados, los deduplica antes de validar.
 *
 * Uso:
 *   const ids = await validateMetalVariantIds(jewelryId, body.metalVariantIds);
 *   // ids: string[] dedup, todos verificados
 */
export async function validateMetalVariantIds(
  jewelryId: string,
  ids: unknown,
): Promise<string[]> {
  if (!Array.isArray(ids)) {
    err("Cuando el alcance es METALS, `metalVariantIds` debe ser un array.");
  }
  const cleanIds = [
    ...new Set(
      (ids as unknown[])
        .filter((v): v is string => typeof v === "string")
        .map((v) => v.trim())
        .filter((v) => v.length > 0),
    ),
  ];
  if (cleanIds.length === 0) {
    err("Cuando el alcance es METALS, debe seleccionarse al menos una variante.");
  }
  const found = await prisma.metalVariant.findMany({
    where: { id: { in: cleanIds }, deletedAt: null },
    select: { id: true, isActive: true, metal: { select: { jewelryId: true } } },
  });
  const foundMap = new Map(found.map((v) => [v.id, v]));
  for (const id of cleanIds) {
    const v = foundMap.get(id);
    if (!v) err(`La variante de metal ${id} no existe o fue eliminada.`);
    if (v!.metal.jewelryId !== jewelryId) {
      err(`La variante de metal ${id} no pertenece al tenant.`);
    }
    if (!v!.isActive) err(`La variante de metal ${id} está inactiva.`);
  }
  return cleanIds;
}
