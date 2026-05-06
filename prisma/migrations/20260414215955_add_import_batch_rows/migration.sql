-- AlterTable
ALTER TABLE "ImportBatch" ADD COLUMN     "status" TEXT NOT NULL DEFAULT 'SUCCESS';

-- CreateTable
CREATE TABLE "ImportBatchRow" (
    "id" TEXT NOT NULL,
    "batchId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "rowIndex" INTEGER NOT NULL,
    "displayName" TEXT NOT NULL DEFAULT '',
    "actionResult" TEXT NOT NULL,
    "identifier" TEXT NOT NULL DEFAULT '',
    "message" TEXT NOT NULL DEFAULT '',
    "errors" JSONB,
    "rawData" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ImportBatchRow_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ImportBatchRow_batchId_idx" ON "ImportBatchRow"("batchId");

-- CreateIndex
CREATE INDEX "ImportBatchRow_batchId_actionResult_idx" ON "ImportBatchRow"("batchId", "actionResult");

-- CreateIndex
CREATE INDEX "ImportBatchRow_jewelryId_idx" ON "ImportBatchRow"("jewelryId");

-- CreateIndex
CREATE INDEX "ImportBatch_jewelryId_status_idx" ON "ImportBatch"("jewelryId", "status");

-- AddForeignKey
ALTER TABLE "ImportBatchRow" ADD CONSTRAINT "ImportBatchRow_batchId_fkey" FOREIGN KEY ("batchId") REFERENCES "ImportBatch"("id") ON DELETE CASCADE ON UPDATE CASCADE;
