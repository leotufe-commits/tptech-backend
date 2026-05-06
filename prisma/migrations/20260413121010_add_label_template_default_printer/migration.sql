-- AlterTable
ALTER TABLE "LabelTemplate" ADD COLUMN     "defaultPrinterProfileId" TEXT;

-- AddForeignKey
ALTER TABLE "LabelTemplate" ADD CONSTRAINT "LabelTemplate_defaultPrinterProfileId_fkey" FOREIGN KEY ("defaultPrinterProfileId") REFERENCES "PrinterProfile"("id") ON DELETE SET NULL ON UPDATE CASCADE;
