-- Add headerLogoShape to DocumentTemplate
ALTER TABLE "DocumentTemplate" ADD COLUMN "headerLogoShape" TEXT NOT NULL DEFAULT 'rounded';
