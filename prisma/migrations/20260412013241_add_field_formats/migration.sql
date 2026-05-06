-- AlterTable
ALTER TABLE "Jewelry" ADD COLUMN     "documentFormat" TEXT NOT NULL DEFAULT 'raw',
ADD COLUMN     "phoneFormat" TEXT NOT NULL DEFAULT 'raw';
