/*
  Warnings:

  - You are about to drop the column `zone` on the `ShippingRate` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "ShippingRate" DROP COLUMN "zone",
ADD COLUMN     "zones" JSONB NOT NULL DEFAULT '[]';
