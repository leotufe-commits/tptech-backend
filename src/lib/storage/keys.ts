function safeSeg(s: string) {
  return String(s || "")
    .trim()
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .slice(0, 120);
}

export function buildObjectKey(args: {
  tenantId: string;
  kind: "user_avatar" | "jewelry_logo" | "attachment" | "product_image" | "product_video";
  userId?: string;
  productId?: string;
  originalName?: string;
  ext?: string;
}) {
  const t = safeSeg(args.tenantId);
  const ext = safeSeg(args.ext || "");
  const name = safeSeg(args.originalName || "file");

  if (args.kind === "user_avatar") {
    const u = safeSeg(args.userId || "user");
    return `tptech/tenants/${t}/avatars/users/${u}${ext ? "." + ext : ""}`;
  }

  if (args.kind === "jewelry_logo") {
    return `tptech/tenants/${t}/jewelry/logo${ext ? "." + ext : ""}`;
  }

  if (args.kind === "product_image") {
    const p = safeSeg(args.productId || "product");
    return `tptech/tenants/${t}/catalog/products/${p}/${Date.now()}_${name}${ext ? "." + ext : ""}`;
  }

  if (args.kind === "product_video") {
    const p = safeSeg(args.productId || "product");
    return `tptech/tenants/${t}/videos/products/${p}/${Date.now()}_${name}${ext ? "." + ext : ""}`;
  }

  // attachment
  return `tptech/tenants/${t}/attachments/${Date.now()}_${name}${ext ? "." + ext : ""}`;
}
