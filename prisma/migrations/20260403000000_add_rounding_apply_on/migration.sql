-- CreateEnum
CREATE TYPE "RoundingApplyOn" AS ENUM ('PRICE', 'NET', 'TOTAL');

-- AlterTable
ALTER TABLE "PriceList" ADD COLUMN "roundingApplyOn" "RoundingApplyOn" NOT NULL DEFAULT 'PRICE';
