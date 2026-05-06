-- AlterTable: agregar sourceType a ArticleMovement
ALTER TABLE "ArticleMovement" ADD COLUMN "sourceType" TEXT NOT NULL DEFAULT 'MANUAL';

-- CreateIndex
CREATE INDEX "ArticleMovement_jewelryId_sourceType_idx" ON "ArticleMovement"("jewelryId", "sourceType");
