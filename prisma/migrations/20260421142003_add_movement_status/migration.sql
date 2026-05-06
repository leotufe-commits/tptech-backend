-- CreateEnum
CREATE TYPE "MovementStatus" AS ENUM ('DRAFT', 'CONFIRMED', 'VOIDED');

-- AlterTable
ALTER TABLE "ArticleMovement" ADD COLUMN     "status" "MovementStatus" NOT NULL DEFAULT 'CONFIRMED';

-- CreateIndex
CREATE INDEX "ArticleMovement_jewelryId_status_idx" ON "ArticleMovement"("jewelryId", "status");
