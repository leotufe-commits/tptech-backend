-- Seed: cargar términos de pago por defecto para todos los tenants existentes
-- (En una migración separada para que el valor PAYMENT_TERM ya esté committed)
INSERT INTO "CatalogItem" (id, "jewelryId", type, label, "isActive", "sortOrder", "isSystem", "isFavorite", "createdAt", "updatedAt")
SELECT
  concat('c', substring(md5(j.id || t.label), 1, 24)) AS id,
  j.id                                                  AS "jewelryId",
  'PAYMENT_TERM'::"CatalogType"                         AS type,
  t.label,
  true                                                  AS "isActive",
  t.sort_order                                          AS "sortOrder",
  true                                                  AS "isSystem",
  false                                                 AS "isFavorite",
  NOW()                                                 AS "createdAt",
  NOW()                                                 AS "updatedAt"
FROM "Jewelry" j
CROSS JOIN (VALUES
  ('Contado',   0),
  ('15 días',   1),
  ('30 días',   2),
  ('60 días',   3),
  ('90 días',   4),
  ('120 días',  5)
) AS t(label, sort_order)
ON CONFLICT ("jewelryId", type, label) DO NOTHING;
