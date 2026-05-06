-- AlterTable: add headerLogoSize and headerShowProductImage to DocumentTemplate
ALTER TABLE "DocumentTemplate" ADD COLUMN "headerLogoSize" TEXT NOT NULL DEFAULT 'md';
ALTER TABLE "DocumentTemplate" ADD COLUMN "headerShowProductImage" BOOLEAN NOT NULL DEFAULT false;
