-- Migration: add_seller_commissions
-- Replaces CommissionBase enum (GROSS/NET/MARGIN → TOTAL/METAL/HECHURA/METAL_Y_HECHURA)
-- Adds sellerCommissionTotal to Sale
-- Adds sellerCommissionBase + sellerCommissionAmount to SaleLine

-- Step 1: create the new enum type
CREATE TYPE "CommissionBase_new" AS ENUM ('TOTAL', 'METAL', 'HECHURA', 'METAL_Y_HECHURA');

-- Step 2: migrate Seller.commissionBase column
--   All existing rows (defaulted to NET or GROSS or MARGIN) become TOTAL
ALTER TABLE "Seller"
  ALTER COLUMN "commissionBase" DROP DEFAULT,
  ALTER COLUMN "commissionBase" TYPE "CommissionBase_new"
    USING ('TOTAL'::"CommissionBase_new"),
  ALTER COLUMN "commissionBase" SET DEFAULT 'TOTAL'::"CommissionBase_new";

-- Step 3: drop old type and rename new type
DROP TYPE "CommissionBase";
ALTER TYPE "CommissionBase_new" RENAME TO "CommissionBase";

-- Step 4: add sellerCommissionTotal to Sale
ALTER TABLE "Sale"
  ADD COLUMN IF NOT EXISTS "sellerCommissionTotal" DECIMAL(14, 2);

-- Step 5: add commission fields to SaleLine
ALTER TABLE "SaleLine"
  ADD COLUMN IF NOT EXISTS "sellerCommissionBase"   DECIMAL(14, 2),
  ADD COLUMN IF NOT EXISTS "sellerCommissionAmount" DECIMAL(14, 2);
