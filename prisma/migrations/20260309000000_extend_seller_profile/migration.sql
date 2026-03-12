-- AlterTable: add new columns to Seller
ALTER TABLE "Seller" ADD COLUMN "avatarUrl" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Seller" ADD COLUMN "street" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Seller" ADD COLUMN "streetNumber" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Seller" ADD COLUMN "city" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Seller" ADD COLUMN "province" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Seller" ADD COLUMN "country" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Seller" ADD COLUMN "postalCode" TEXT NOT NULL DEFAULT '';

-- CreateTable: SellerAttachment
CREATE TABLE "SellerAttachment" (
    "id" TEXT NOT NULL,
    "sellerId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL DEFAULT '',
    "size" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "SellerAttachment_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "SellerAttachment_sellerId_idx" ON "SellerAttachment"("sellerId");
CREATE INDEX "SellerAttachment_jewelryId_idx" ON "SellerAttachment"("jewelryId");
CREATE INDEX "SellerAttachment_deletedAt_idx" ON "SellerAttachment"("deletedAt");

-- AddForeignKey
ALTER TABLE "SellerAttachment" ADD CONSTRAINT "SellerAttachment_sellerId_fkey" FOREIGN KEY ("sellerId") REFERENCES "Seller"("id") ON DELETE CASCADE ON UPDATE CASCADE;
