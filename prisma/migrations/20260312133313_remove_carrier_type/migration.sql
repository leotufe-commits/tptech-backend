/*
  Warnings:

  - You are about to drop the column `provider` on the `ShippingCarrier` table. All the data in the column will be lost.
  - You are about to drop the column `providerConfig` on the `ShippingCarrier` table. All the data in the column will be lost.
  - You are about to drop the column `type` on the `ShippingCarrier` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "ShippingCarrier_jewelryId_type_idx";

-- AlterTable
ALTER TABLE "ShippingCarrier" DROP COLUMN "provider",
DROP COLUMN "providerConfig",
DROP COLUMN "type";

-- DropEnum
DROP TYPE "ShippingCarrierType";
