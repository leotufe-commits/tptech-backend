-- Backfill: el Cliente pasa de DECIDIR a SUGERIR (contrato Balance Mode 2026-06-14).
--
-- El nivel "Cliente" de la jerarquía R11.4 ahora se resuelve EXCLUSIVAMENTE con
-- el campo canónico `balanceMode` (nullable): `NULL` = "sin preferencia" -> el
-- cliente delega en el resto de la cadena (Mis preferencias -> Lista -> Joyeria
-- -> fallback). El legacy `balanceType` (no-null) dejo de participar de la
-- resolucion.
--
-- Para que los clientes EXISTENTES conserven su comportamiento actual (que venia
-- del legacy `balanceType`), copiamos ese valor a `balanceMode` en todas las
-- filas que aun no tienen preferencia canonica. Asi la historia se preserva por
-- DATA y nunca por reinterpretacion en runtime.
--
-- Idempotente: solo toca filas con `balanceMode` NULL. Re-ejecutar no cambia nada.
UPDATE "CommercialEntity"
SET "balanceMode" = "balanceType"::text::"BalanceMode"
WHERE "balanceMode" IS NULL;
