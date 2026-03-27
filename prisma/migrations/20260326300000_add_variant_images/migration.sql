-- CreateTable: ArticleVariantImage (galería de imágenes por variante)
CREATE TABLE "ArticleVariantImage" (
    "id" TEXT NOT NULL,
    "variantId" TEXT NOT NULL,
    "articleId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "label" TEXT NOT NULL DEFAULT '',
    "isMain" BOOLEAN NOT NULL DEFAULT false,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ArticleVariantImage_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ArticleVariantImage_variantId_idx" ON "ArticleVariantImage"("variantId");
CREATE INDEX "ArticleVariantImage_articleId_idx" ON "ArticleVariantImage"("articleId");
CREATE INDEX "ArticleVariantImage_jewelryId_idx" ON "ArticleVariantImage"("jewelryId");

-- AddForeignKey
ALTER TABLE "ArticleVariantImage" ADD CONSTRAINT "ArticleVariantImage_variantId_fkey"
    FOREIGN KEY ("variantId") REFERENCES "ArticleVariant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Data migration: copiar imageUrl existente → ArticleVariantImage (imagen principal)
-- Solo para variantes que tengan imageUrl no vacío
INSERT INTO "ArticleVariantImage" ("id", "variantId", "articleId", "jewelryId", "url", "label", "isMain", "sortOrder", "createdAt")
SELECT
    gen_random_uuid()::text,
    v."id",
    v."articleId",
    v."jewelryId",
    v."imageUrl",
    '',
    true,
    0,
    NOW()
FROM "ArticleVariant" v
WHERE v."imageUrl" IS NOT NULL AND v."imageUrl" != '';
