/*
  Warnings:

  - You are about to drop the column `totalWeight` on the `ArticleMovementLine` table. All the data in the column will be lost.
  - You are about to drop the column `weightPerUnit` on the `ArticleMovementLine` table. All the data in the column will be lost.
  - You are about to drop the column `defaultQuantity` on the `ArticleVariant` table. All the data in the column will be lost.
  - You are about to drop the column `maxSaleQuantity` on the `ArticleVariant` table. All the data in the column will be lost.
  - You are about to drop the column `minSaleQuantity` on the `ArticleVariant` table. All the data in the column will be lost.
  - You are about to drop the column `themePreference` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `apartment` on the `Warehouse` table. All the data in the column will be lost.
  - You are about to drop the column `email` on the `Warehouse` table. All the data in the column will be lost.
  - You are about to drop the column `floor` on the `Warehouse` table. All the data in the column will be lost.
  - You are about to drop the `WarehouseAttachment` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "WarehouseAttachment" DROP CONSTRAINT "WarehouseAttachment_warehouseId_fkey";

-- AlterTable
ALTER TABLE "Article" ALTER COLUMN "barcodeSource" SET DEFAULT 'CUSTOM';

-- AlterTable
ALTER TABLE "ArticleMovementLine" DROP COLUMN "totalWeight",
DROP COLUMN "weightPerUnit";

-- AlterTable
ALTER TABLE "ArticleVariant" DROP COLUMN "defaultQuantity",
DROP COLUMN "maxSaleQuantity",
DROP COLUMN "minSaleQuantity",
ALTER COLUMN "barcodeSource" SET DEFAULT 'CUSTOM';

-- AlterTable
ALTER TABLE "User" DROP COLUMN "themePreference";

-- AlterTable
ALTER TABLE "Warehouse" DROP COLUMN "apartment",
DROP COLUMN "email",
DROP COLUMN "floor";

-- DropTable
DROP TABLE "WarehouseAttachment";
