-- AlterTable
ALTER TABLE "CommercialEntity" ADD COLUMN     "commercialApplyOn" "CommercialApplyOn",
ADD COLUMN     "commercialRuleType" "CommercialRuleType",
ADD COLUMN     "commercialValue" DECIMAL(14,4),
ADD COLUMN     "commercialValueType" "CommercialValueType";
