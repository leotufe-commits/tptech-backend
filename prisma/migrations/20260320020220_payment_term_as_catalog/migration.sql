-- AlterEnum
ALTER TYPE "CatalogType" ADD VALUE IF NOT EXISTS 'PAYMENT_TERM';

-- DropForeignKey
ALTER TABLE "CommercialEntity" DROP CONSTRAINT IF EXISTS "CommercialEntity_paymentTermId_fkey";

-- DropIndex
DROP INDEX IF EXISTS "CommercialEntity_paymentTermId_idx";

-- AlterTable
ALTER TABLE "CommercialEntity"
  DROP COLUMN IF EXISTS "paymentTermId",
  ADD COLUMN IF NOT EXISTS "paymentTerm" TEXT NOT NULL DEFAULT '';

-- DropTable
DROP TABLE IF EXISTS "PaymentTerm";
