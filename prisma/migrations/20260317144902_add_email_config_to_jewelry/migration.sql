/*
  Warnings:

  - A unique constraint covering the columns `[userId]` on the table `Seller` will be added. If there are existing duplicate values, this will fail.

*/
-- DropIndex
DROP INDEX "Seller_userId_key";

-- AlterTable
ALTER TABLE "Jewelry" ADD COLUMN     "emailAddressLine" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "emailBusinessHours" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "emailContact" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "emailEnabled" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "emailFooter" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "emailInstagram" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "emailLogoUrl" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "emailPhone" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "emailReplyTo" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "emailSenderName" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "emailSignature" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "emailWebsite" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "emailWhatsapp" TEXT NOT NULL DEFAULT '';

-- CreateIndex
CREATE UNIQUE INDEX "Seller_userId_key" ON "Seller"("userId");
