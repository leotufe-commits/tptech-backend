-- AlterTable
ALTER TABLE "Promotion" ADD COLUMN     "applyOn" "CommercialApplyOn" NOT NULL DEFAULT 'TOTAL';

-- AlterTable
ALTER TABLE "QuantityDiscount" ADD COLUMN     "applyOn" "CommercialApplyOn" NOT NULL DEFAULT 'TOTAL';
