-- Agregar legalName a Jewelry (snapshot fiscal del emisor en comprobantes)
ALTER TABLE "Jewelry"
  ADD COLUMN IF NOT EXISTS "legalName" TEXT NOT NULL DEFAULT '';
