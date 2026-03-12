-- CreateEnum
CREATE TYPE "CommissionBase" AS ENUM ('GROSS', 'NET', 'MARGIN');

-- AlterTable
ALTER TABLE "Seller" ADD COLUMN     "commissionBase" "CommissionBase" NOT NULL DEFAULT 'NET';
