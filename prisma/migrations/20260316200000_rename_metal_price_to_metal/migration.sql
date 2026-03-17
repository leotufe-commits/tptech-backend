-- Rename enum value METAL_PRICE → METAL in CommercialApplyOn
-- Compatible with PostgreSQL 10+. Safe: no existing data to update since
-- EntityCommercialRule was just created in migration 20260316123438.
ALTER TYPE "CommercialApplyOn" RENAME VALUE 'METAL_PRICE' TO 'METAL';
