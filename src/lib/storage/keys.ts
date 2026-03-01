function safeSeg(s: string) {
  return String(s || "")
    .trim()
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .slice(0, 120);
}

export type StorageKind =
  | "user_avatar"
  | "jewelry_logo"
  | "product_image"
  | "product_video"
  | "attachment"
  | "document";

export function buildObjectKey(args: {
  tenantId: string;
  kind: StorageKind;
  userId?: string;
  productId?: string;
  originalName?: string;
  ext?: string;
}) {
  const t = safeSeg(args.tenantId);
  const ext = safeSeg(args.ext || "");
  const name = safeSeg(args.originalName || "file");

  const suffix = ext ? "." + ext : "";

  switch (args.kind) {
    case "user_avatar": {
      const u = safeSeg(args.userId || "user");
      return `tptech/tenants/${t}/avatars/users/${u}${suffix}`;
    }

    case "jewelry_logo": {
      // ✅ Cache-busting profesional (evita problemas de CDN / browser cache)
      return `tptech/tenants/${t}/jewelry/logo_${Date.now()}${suffix}`;
    }

    case "product_image": {
      const p = safeSeg(args.productId || "product");
      return `tptech/tenants/${t}/catalog/products/${p}/${Date.now()}_${name}${suffix}`;
    }

    case "product_video": {
      const p = safeSeg(args.productId || "product");
      return `tptech/tenants/${t}/videos/products/${p}/${Date.now()}_${name}${suffix}`;
    }

    case "attachment":
    case "document": {
      return `tptech/tenants/${t}/attachments/${Date.now()}_${name}${suffix}`;
    }

    default:
      throw new Error("Invalid storage kind");
  }
}