-- CreateTable
CREATE TABLE "ArticleCategory" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "parentId" TEXT,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "imageUrl" TEXT NOT NULL DEFAULT '',
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ArticleCategory_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ArticleCategory_jewelryId_idx" ON "ArticleCategory"("jewelryId");
CREATE INDEX "ArticleCategory_jewelryId_isActive_idx" ON "ArticleCategory"("jewelryId", "isActive");
CREATE INDEX "ArticleCategory_parentId_idx" ON "ArticleCategory"("parentId");
CREATE INDEX "ArticleCategory_jewelryId_deletedAt_idx" ON "ArticleCategory"("jewelryId", "deletedAt");
CREATE INDEX "ArticleCategory_deletedAt_idx" ON "ArticleCategory"("deletedAt");

-- AddForeignKey
ALTER TABLE "ArticleCategory" ADD CONSTRAINT "ArticleCategory_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleCategory" ADD CONSTRAINT "ArticleCategory_parentId_fkey" FOREIGN KEY ("parentId") REFERENCES "ArticleCategory"("id") ON DELETE SET NULL ON UPDATE CASCADE;
