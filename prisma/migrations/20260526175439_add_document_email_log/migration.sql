-- CreateTable
CREATE TABLE "DocumentEmailLog" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "documentKind" TEXT NOT NULL,
    "documentId" TEXT NOT NULL,
    "saleId" TEXT,
    "recipientEmail" TEXT NOT NULL,
    "subjectSnapshot" TEXT NOT NULL,
    "bodySnapshot" TEXT NOT NULL,
    "attachmentFilename" TEXT,
    "provider" TEXT NOT NULL,
    "providerMessageId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'SENT',
    "sentByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DocumentEmailLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "DocumentEmailLog_jewelryId_documentKind_documentId_createdA_idx" ON "DocumentEmailLog"("jewelryId", "documentKind", "documentId", "createdAt");

