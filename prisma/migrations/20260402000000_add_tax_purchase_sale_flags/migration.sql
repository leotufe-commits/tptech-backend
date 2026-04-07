-- Migration: add appliesOnSale, appliesOnPurchase, isRecoverable to Tax
-- All default to maintain backwards-compatible behavior:
--   appliesOnSale=true     → existing taxes keep applying on sale
--   appliesOnPurchase=true → existing taxes keep applying on purchase
--   isRecoverable=false    → existing taxes keep summing to cost (non-recoverable)

ALTER TABLE "Tax" ADD COLUMN "appliesOnSale"     BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "Tax" ADD COLUMN "appliesOnPurchase" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "Tax" ADD COLUMN "isRecoverable"     BOOLEAN NOT NULL DEFAULT false;
