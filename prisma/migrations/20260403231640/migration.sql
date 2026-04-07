-- DropForeignKey
ALTER TABLE "PromotionGroup" DROP CONSTRAINT "PromotionGroup_groupId_fkey";

-- DropForeignKey
ALTER TABLE "PromotionGroup" DROP CONSTRAINT "PromotionGroup_promotionId_fkey";

-- DropForeignKey
ALTER TABLE "QuantityDiscount" DROP CONSTRAINT "QuantityDiscount_groupId_fkey";

-- AddForeignKey
ALTER TABLE "PromotionGroup" ADD CONSTRAINT "PromotionGroup_promotionId_fkey" FOREIGN KEY ("promotionId") REFERENCES "Promotion"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PromotionGroup" ADD CONSTRAINT "PromotionGroup_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "ArticleGroup"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "QuantityDiscount" ADD CONSTRAINT "QuantityDiscount_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "ArticleGroup"("id") ON DELETE SET NULL ON UPDATE CASCADE;
