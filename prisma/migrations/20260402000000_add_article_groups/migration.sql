-- CreateTable
CREATE TABLE "ArticleGroup" (
    "id"            TEXT NOT NULL,
    "jewelryId"     TEXT NOT NULL,
    "name"          TEXT NOT NULL,
    "slug"          TEXT NOT NULL,
    "description"   TEXT NOT NULL DEFAULT '',
    "mainImageUrl"  TEXT NOT NULL DEFAULT '',
    "selectorLabel" TEXT NOT NULL DEFAULT '',
    "isActive"      BOOLEAN NOT NULL DEFAULT true,
    "createdAt"     TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"     TIMESTAMP(3) NOT NULL,
    "deletedAt"     TIMESTAMP(3),

    CONSTRAINT "ArticleGroup_pkey" PRIMARY KEY ("id")
);

-- AlterTable
ALTER TABLE "Article" ADD COLUMN "groupId" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "ArticleGroup_jewelryId_slug_key" ON "ArticleGroup"("jewelryId", "slug");

-- CreateIndex
CREATE INDEX "ArticleGroup_jewelryId_idx" ON "ArticleGroup"("jewelryId");

-- CreateIndex
CREATE INDEX "ArticleGroup_deletedAt_idx" ON "ArticleGroup"("deletedAt");

-- CreateIndex
CREATE INDEX "Article_groupId_idx" ON "Article"("groupId");

-- AddForeignKey
ALTER TABLE "ArticleGroup" ADD CONSTRAINT "ArticleGroup_jewelryId_fkey"
    FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Article" ADD CONSTRAINT "Article_groupId_fkey"
    FOREIGN KEY ("groupId") REFERENCES "ArticleGroup"("id") ON DELETE SET NULL ON UPDATE CASCADE;
