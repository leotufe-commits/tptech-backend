-- Add GROUP to PromotionScope enum
ALTER TYPE "PromotionScope" ADD VALUE IF NOT EXISTS 'GROUP';

-- Add GROUP_TOTAL to QuantityDiscountEvaluationMode enum
ALTER TYPE "QuantityDiscountEvaluationMode" ADD VALUE IF NOT EXISTS 'GROUP_TOTAL';

-- Add groupId to QuantityDiscount
ALTER TABLE "QuantityDiscount" ADD COLUMN "groupId" TEXT;
ALTER TABLE "QuantityDiscount" ADD CONSTRAINT "QuantityDiscount_groupId_fkey"
  FOREIGN KEY ("groupId") REFERENCES "ArticleGroup"("id") ON DELETE SET NULL;
CREATE INDEX "QuantityDiscount_groupId_idx" ON "QuantityDiscount"("groupId");

-- Create PromotionGroup junction table
CREATE TABLE "PromotionGroup" (
  "id"          TEXT NOT NULL,
  "promotionId" TEXT NOT NULL,
  "groupId"     TEXT NOT NULL,
  "jewelryId"   TEXT NOT NULL,

  CONSTRAINT "PromotionGroup_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "PromotionGroup" ADD CONSTRAINT "PromotionGroup_promotionId_fkey"
  FOREIGN KEY ("promotionId") REFERENCES "Promotion"("id") ON DELETE CASCADE;
ALTER TABLE "PromotionGroup" ADD CONSTRAINT "PromotionGroup_groupId_fkey"
  FOREIGN KEY ("groupId") REFERENCES "ArticleGroup"("id") ON DELETE CASCADE;

CREATE UNIQUE INDEX "PromotionGroup_promotionId_groupId_key" ON "PromotionGroup"("promotionId", "groupId");
CREATE INDEX "PromotionGroup_promotionId_idx" ON "PromotionGroup"("promotionId");
CREATE INDEX "PromotionGroup_groupId_idx" ON "PromotionGroup"("groupId");
CREATE INDEX "PromotionGroup_jewelryId_idx" ON "PromotionGroup"("jewelryId");
