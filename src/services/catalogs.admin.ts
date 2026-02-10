// tptech-frontend/src/services/catalogs.admin.ts
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
  createdAt: string;
  updatedAt: string;
};

/**
 * ✅ Devuelve ARRAY directo (CatalogItem[])
 * includeInactive default true (admin generalmente ve todo)
 */
export async function listCatalogAdmin(
  type: CatalogType,
  opts?: { includeInactive?: boolean; force?: boolean }
): Promise<CatalogItem[]> {
  const qs = new URLSearchParams();

  const includeInactive = opts?.includeInactive ?? true;
  if (includeInactive) qs.set("includeInactive", "1");

  // cache-bust opcional (por si querés forzar refresh)
  if (opts?.force) qs.set("_ts", String(Date.now()));

  const suffix = qs.toString() ? `?${qs.toString()}` : "";

  const resp = await apiFetch<{ items: CatalogItem[] }>(`/company/catalogs/${type}${suffix}`);

  const items = (resp as any)?.items ?? resp;
  return Array.isArray(items) ? (items as CatalogItem[]) : [];
}

export async function createCatalogItemAdmin(type: CatalogType, label: string, sortOrder = 0) {
  return apiFetch<{ item: CatalogItem; created: boolean }>(`/company/catalogs/${type}`, {
    method: "POST",
    body: { label, sortOrder }, // ✅ apiFetch serializa
  });
}

export async function bulkCreateCatalogItemsAdmin(type: CatalogType, labels: string[], sortOrderStart = 0) {
  return apiFetch<{ ok: boolean; requested: number; created: number; skipped: number }>(
    `/company/catalogs/${type}/bulk`,
    {
      method: "POST",
      body: { labels, sortOrderStart }, // ✅ apiFetch serializa
    }
  );
}

export async function updateCatalogItemAdmin(
  id: string,
  patch: Partial<Pick<CatalogItem, "label" | "isActive" | "sortOrder">>
) {
  return apiFetch<{ item: CatalogItem }>(`/company/catalogs/item/${id}`, {
    method: "PATCH",
    body: patch, // ✅ apiFetch serializa
  });
}
