-- AlterTable
ALTER TABLE "Jewelry" ADD COLUMN     "cuit" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "email" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "ivaCondition" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "legalName" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "logoUrl" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "notes" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "website" TEXT NOT NULL DEFAULT '';

-- CreateTable
CREATE TABLE "JewelryAttachment" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL,
    "size" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "JewelryAttachment_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "JewelryAttachment_jewelryId_idx" ON "JewelryAttachment"("jewelryId");

-- CreateIndex
CREATE INDEX "JewelryAttachment_createdAt_idx" ON "JewelryAttachment"("createdAt");

-- AddForeignKey
ALTER TABLE "JewelryAttachment" ADD CONSTRAINT "JewelryAttachment_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
