-- CreateEnum
CREATE TYPE "QuantityDiscountEvaluationMode" AS ENUM ('LINE', 'CATEGORY_TOTAL', 'BRAND_TOTAL');

-- AlterTable
ALTER TABLE "QuantityDiscount" ADD COLUMN "evaluationMode" "QuantityDiscountEvaluationMode" NOT NULL DEFAULT 'LINE';
