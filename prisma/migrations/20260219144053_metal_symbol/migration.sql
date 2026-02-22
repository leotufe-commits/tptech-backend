/*
  Warnings:

  - A unique constraint covering the columns `[jewelryId,symbol]` on the table `Metal` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "Metal" ADD COLUMN     "symbol" TEXT NOT NULL DEFAULT '';

-- CreateIndex
CREATE UNIQUE INDEX "Metal_jewelryId_symbol_key" ON "Metal"("jewelryId", "symbol");
