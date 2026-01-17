-- AlterTable
ALTER TABLE "User" ADD COLUMN     "city" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "country" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "documentNumber" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "documentType" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "notes" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "number" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "phoneCountry" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "phoneNumber" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "postalCode" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "province" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "street" TEXT NOT NULL DEFAULT '';

-- CreateTable
CREATE TABLE "UserAttachment" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL,
    "size" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UserAttachment_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "UserAttachment_userId_idx" ON "UserAttachment"("userId");

-- CreateIndex
CREATE INDEX "UserAttachment_createdAt_idx" ON "UserAttachment"("createdAt");

-- AddForeignKey
ALTER TABLE "UserAttachment" ADD CONSTRAINT "UserAttachment_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
