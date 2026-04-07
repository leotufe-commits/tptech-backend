-- AlterTable
ALTER TABLE "SaleLine" ADD COLUMN     "taxAmount" DECIMAL(14,4),
ADD COLUMN     "taxSnapshot" JSONB;
