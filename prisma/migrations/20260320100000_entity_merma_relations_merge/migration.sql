-- CreateEnum
CREATE TYPE "EntityRelationType" AS ENUM ('CLIENT_OF', 'SUPPLIES_TO', 'SAME_GROUP', 'RELATED_COMPANY', 'REFERRED_BY', 'OTHER');

-- AddForeignKey to mergedIntoEntityId (self-referential)
ALTER TABLE "CommercialEntity" ADD CONSTRAINT "CommercialEntity_mergedIntoEntityId_fkey"
  FOREIGN KEY ("mergedIntoEntityId") REFERENCES "CommercialEntity"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

CREATE INDEX "CommercialEntity_mergedIntoEntityId_idx" ON "CommercialEntity"("mergedIntoEntityId");

-- CreateTable EntityMermaOverride
CREATE TABLE "EntityMermaOverride" (
    "id" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "variantId" TEXT NOT NULL,
    "role" "EntityRole" NOT NULL DEFAULT 'CLIENT',
    "mermaPercent" DECIMAL(5,2) NOT NULL,
    "notes" TEXT NOT NULL DEFAULT '',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "EntityMermaOverride_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "EntityMermaOverride_entityId_variantId_role_key" ON "EntityMermaOverride"("entityId", "variantId", "role");
CREATE INDEX "EntityMermaOverride_entityId_idx" ON "EntityMermaOverride"("entityId");
CREATE INDEX "EntityMermaOverride_jewelryId_idx" ON "EntityMermaOverride"("jewelryId");
CREATE INDEX "EntityMermaOverride_variantId_idx" ON "EntityMermaOverride"("variantId");
CREATE INDEX "EntityMermaOverride_deletedAt_idx" ON "EntityMermaOverride"("deletedAt");

ALTER TABLE "EntityMermaOverride" ADD CONSTRAINT "EntityMermaOverride_entityId_fkey"
  FOREIGN KEY ("entityId") REFERENCES "CommercialEntity"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "EntityMermaOverride" ADD CONSTRAINT "EntityMermaOverride_variantId_fkey"
  FOREIGN KEY ("variantId") REFERENCES "MetalVariant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- CreateTable EntityRelation
CREATE TABLE "EntityRelation" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "fromEntityId" TEXT NOT NULL,
    "toEntityId" TEXT NOT NULL,
    "relationType" "EntityRelationType" NOT NULL DEFAULT 'OTHER',
    "notes" TEXT NOT NULL DEFAULT '',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "EntityRelation_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "EntityRelation_fromEntityId_toEntityId_relationType_key" ON "EntityRelation"("fromEntityId", "toEntityId", "relationType");
CREATE INDEX "EntityRelation_jewelryId_idx" ON "EntityRelation"("jewelryId");
CREATE INDEX "EntityRelation_fromEntityId_idx" ON "EntityRelation"("fromEntityId");
CREATE INDEX "EntityRelation_toEntityId_idx" ON "EntityRelation"("toEntityId");
CREATE INDEX "EntityRelation_deletedAt_idx" ON "EntityRelation"("deletedAt");

ALTER TABLE "EntityRelation" ADD CONSTRAINT "EntityRelation_fromEntityId_fkey"
  FOREIGN KEY ("fromEntityId") REFERENCES "CommercialEntity"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "EntityRelation" ADD CONSTRAINT "EntityRelation_toEntityId_fkey"
  FOREIGN KEY ("toEntityId") REFERENCES "CommercialEntity"("id") ON DELETE CASCADE ON UPDATE CASCADE;
