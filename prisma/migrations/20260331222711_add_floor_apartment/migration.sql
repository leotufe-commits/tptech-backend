-- AlterTable
ALTER TABLE "Jewelry" ADD COLUMN     "apartment" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "floor" TEXT NOT NULL DEFAULT '';

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "apartment" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "floor" TEXT NOT NULL DEFAULT '';
