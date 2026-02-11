// tptech-backend/src/services/catalogs.ts
import { apiFetch } from "../lib/api.js";

export type CatalogType =
  | "IVA_CONDITION"
  | "DOCUMENT_TYPE"
  | "PHONE_PREFIX"
  | "CITY"
  | "PROVINCE"
  | "COUNTRY";

export type CatalogItem = {
  id: string;
  type: CatalogType;
  label: string;
  isActive: boolean;
  sortOrder: number;

  // ✅ opcional (por compatibilidad)
  isFavorite?: boolean;

  createdAt?: string;
  updatedAt?: string;
};

/**
 * ✅ Devuelve ARRAY directo (CatalogItem[])
 * opts:
 * - includeInactive: ver inactivos (admin)
 * - force: cache-bust (si tenés caches arriba)
 */
export async function listCatalog(
  type: CatalogType,
  opts?: { includeInactive?: boolean; force?: boolean }
): Promise<CatalogItem[]> {
  const qs = new URLSearchParams();

  if (opts?.includeInactive) qs.set("includeInactive", "1");
  if (opts?.force) qs.set("_ts", String(Date.now()));

  const suffix = qs.toString() ? `?${qs.toString()}` : "";

  // El backend puede devolver { items } o array directo (por robustez)
  const resp = await apiFetch<any>(`/company/catalogs/${type}${suffix}`);
  const items = (resp as any)?.items ?? resp;

  return Array.isArray(items) ? (items as CatalogItem[]) : [];
}

export async function createCatalogItem(type: CatalogType, label: string, sortOrder = 0) {
  return apiFetch<{ item: CatalogItem; created?: boolean }>(`/company/catalogs/${type}`, {
    method: "POST",
    body: { label, sortOrder },
  });
}

export async function bulkCreateCatalogItems(type: CatalogType, labels: string[], sortOrderStart = 0) {
  return apiFetch<{ ok: boolean; requested: number; created: number; skipped: number }>(
    `/company/catalogs/${type}/bulk`,
    {
      method: "POST",
      body: { labels, sortOrderStart },
    }
  );
}

export async function updateCatalogItem(
  id: string,
  patch: Partial<{ label: string; isActive: boolean; sortOrder: number; isFavorite: boolean }>
) {
  return apiFetch<{ item: CatalogItem }>(`/company/catalogs/item/${id}`, {
    method: "PATCH",
    body: patch,
  });
}

/**
 * ✅ Endpoint dedicado a favorito
 * PATCH /company/catalogs/item/:id/favorite
 * Body: { isFavorite: boolean }
 */
export async function setCatalogItemFavorite(id: string, isFavorite: boolean) {
  return apiFetch<{ item: CatalogItem }>(`/company/catalogs/item/${id}/favorite`, {
    method: "PATCH",
    body: { isFavorite },
  });
}
