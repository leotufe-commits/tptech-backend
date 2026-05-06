/*
  Warnings:

  - The values [LOGISTICS] on the enum `CostLineType` will be removed. If these variants are still used in the database, this will fail.
  - You are about to drop the column `legalName` on the `Jewelry` table. All the data in the column will be lost.
  - You are about to drop the `CurrentAccountMovement` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `Receipt` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `ReceiptLine` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `ReceiptSeries` table. If the table is not empty, all the data it contains will be lost.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "CostLineType_new" AS ENUM ('METAL', 'HECHURA', 'PRODUCT', 'SERVICE', 'MANUAL');
ALTER TABLE "public"."ArticleCostLine" ALTER COLUMN "type" DROP DEFAULT;
ALTER TABLE "ArticleCostLine" ALTER COLUMN "type" TYPE "CostLineType_new" USING ("type"::text::"CostLineType_new");
ALTER TYPE "CostLineType" RENAME TO "CostLineType_old";
ALTER TYPE "CostLineType_new" RENAME TO "CostLineType";
DROP TYPE "public"."CostLineType_old";
ALTER TABLE "ArticleCostLine" ALTER COLUMN "type" SET DEFAULT 'MANUAL';
COMMIT;

-- DropForeignKey
ALTER TABLE "CurrentAccountMovement" DROP CONSTRAINT "CurrentAccountMovement_entityId_fkey";

-- DropForeignKey
ALTER TABLE "CurrentAccountMovement" DROP CONSTRAINT "CurrentAccountMovement_jewelryId_fkey";

-- DropForeignKey
ALTER TABLE "CurrentAccountMovement" DROP CONSTRAINT "CurrentAccountMovement_receiptId_fkey";

-- DropForeignKey
ALTER TABLE "Receipt" DROP CONSTRAINT "Receipt_correctedReceiptId_fkey";

-- DropForeignKey
ALTER TABLE "Receipt" DROP CONSTRAINT "Receipt_counterpartyId_fkey";

-- DropForeignKey
ALTER TABLE "Receipt" DROP CONSTRAINT "Receipt_issuedById_fkey";

-- DropForeignKey
ALTER TABLE "Receipt" DROP CONSTRAINT "Receipt_jewelryId_fkey";

-- DropForeignKey
ALTER TABLE "Receipt" DROP CONSTRAINT "Receipt_purchaseId_fkey";

-- DropForeignKey
ALTER TABLE "Receipt" DROP CONSTRAINT "Receipt_saleId_fkey";

-- DropForeignKey
ALTER TABLE "Receipt" DROP CONSTRAINT "Receipt_seriesId_fkey";

-- DropForeignKey
ALTER TABLE "Receipt" DROP CONSTRAINT "Receipt_voidedById_fkey";

-- DropForeignKey
ALTER TABLE "ReceiptLine" DROP CONSTRAINT "ReceiptLine_articleId_fkey";

-- DropForeignKey
ALTER TABLE "ReceiptLine" DROP CONSTRAINT "ReceiptLine_jewelryId_fkey";

-- DropForeignKey
ALTER TABLE "ReceiptLine" DROP CONSTRAINT "ReceiptLine_receiptId_fkey";

-- DropForeignKey
ALTER TABLE "ReceiptLine" DROP CONSTRAINT "ReceiptLine_variantId_fkey";

-- DropForeignKey
ALTER TABLE "ReceiptSeries" DROP CONSTRAINT "ReceiptSeries_jewelryId_fkey";

-- AlterTable
ALTER TABLE "Jewelry" DROP COLUMN "legalName";

-- DropTable
DROP TABLE "CurrentAccountMovement";

-- DropTable
DROP TABLE "Receipt";

-- DropTable
DROP TABLE "ReceiptLine";

-- DropTable
DROP TABLE "ReceiptSeries";

-- DropEnum
DROP TYPE "AccountMovementKind";

-- DropEnum
DROP TYPE "AccountMovementSource";

-- DropEnum
DROP TYPE "ReceiptDirection";

-- DropEnum
DROP TYPE "ReceiptStatus";

-- DropEnum
DROP TYPE "ReceiptType";
