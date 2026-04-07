-- Migration: change roundingApplyOn default from PRICE to TOTAL
-- Also update existing rows that have active rounding configured (roundingTarget != 'NONE')
-- to use TOTAL, since PRICE was the silent default — not a user-conscious choice.

-- 1. Update rows with active rounding from PRICE (old default) to TOTAL (new default)
UPDATE "PriceList"
SET "roundingApplyOn" = 'TOTAL'
WHERE "roundingTarget" != 'NONE'
  AND "roundingApplyOn" = 'PRICE';

-- 2. Change the column default for all future INSERTs
ALTER TABLE "PriceList" ALTER COLUMN "roundingApplyOn" SET DEFAULT 'TOTAL';
