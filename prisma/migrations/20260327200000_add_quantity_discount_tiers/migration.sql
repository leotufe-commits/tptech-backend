-- CreateTable
CREATE TABLE "QuantityDiscountTier" (
    "id" TEXT NOT NULL,
    "discountId" TEXT NOT NULL,
    "minQty" DECIMAL(14,4) NOT NULL,
    "type" "PromotionType" NOT NULL,
    "value" DECIMAL(14,4) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "QuantityDiscountTier_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "QuantityDiscountTier_discountId_idx" ON "QuantityDiscountTier"("discountId");

-- AddForeignKey
ALTER TABLE "QuantityDiscountTier" ADD CONSTRAINT "QuantityDiscountTier_discountId_fkey" FOREIGN KEY ("discountId") REFERENCES "QuantityDiscount"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Migrate existing data: create one tier per existing QuantityDiscount row
INSERT INTO "QuantityDiscountTier" ("id", "discountId", "minQty", "type", "value", "createdAt", "updatedAt")
SELECT
    gen_random_uuid()::text,
    "id",
    "minQty",
    "type",
    "value",
    NOW(),
    NOW()
FROM "QuantityDiscount";

-- AlterTable: remove old columns
ALTER TABLE "QuantityDiscount" DROP COLUMN "minQty";
ALTER TABLE "QuantityDiscount" DROP COLUMN "type";
ALTER TABLE "QuantityDiscount" DROP COLUMN "value";
