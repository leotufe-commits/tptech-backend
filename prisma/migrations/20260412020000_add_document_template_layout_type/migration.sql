-- Add layoutType column to DocumentTemplate
ALTER TABLE "DocumentTemplate" ADD COLUMN "layoutType" TEXT NOT NULL DEFAULT 'A4';

-- Drop old unique constraint (jewelryId, kind)
DROP INDEX "DocumentTemplate_jewelryId_kind_key";

-- Create new unique constraint (jewelryId, kind, layoutType)
CREATE UNIQUE INDEX "DocumentTemplate_jewelryId_kind_layoutType_key" ON "DocumentTemplate"("jewelryId", "kind", "layoutType");
