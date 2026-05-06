-- AlterTable: agregar posición del logo y cambiar default de tamaño a numérico
ALTER TABLE "DocumentTemplate" ADD COLUMN "headerLogoPosition" TEXT NOT NULL DEFAULT 'left';

-- Migrar valores legacy sm/md/lg a mm numérico
UPDATE "DocumentTemplate" SET "headerLogoSize" = '12' WHERE "headerLogoSize" = 'sm';
UPDATE "DocumentTemplate" SET "headerLogoSize" = '18' WHERE "headerLogoSize" = 'md';
UPDATE "DocumentTemplate" SET "headerLogoSize" = '25' WHERE "headerLogoSize" = 'lg';
