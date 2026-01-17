/*
  Warnings:

  - A unique constraint covering the columns `[jewelryId,email]` on the table `User` will be added. If there are existing duplicate values, this will fail.

*/
-- DropIndex
DROP INDEX "User_email_key";

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "quickPinEnabled" BOOLEAN NOT NULL DEFAULT false;

-- CreateIndex
CREATE INDEX "User_quickPinEnabled_idx" ON "User"("quickPinEnabled");

-- CreateIndex
CREATE UNIQUE INDEX "User_jewelryId_email_key" ON "User"("jewelryId", "email");
