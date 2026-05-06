-- Replace headerLogoShape (fixed enum) with headerLogoBorderRadius (0-100 slider)
ALTER TABLE "DocumentTemplate" DROP COLUMN IF EXISTS "headerLogoShape";
ALTER TABLE "DocumentTemplate" ADD COLUMN "headerLogoBorderRadius" INTEGER NOT NULL DEFAULT 20;
