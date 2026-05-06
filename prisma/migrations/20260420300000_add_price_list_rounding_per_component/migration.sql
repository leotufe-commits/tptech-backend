-- AddColumn: roundingModeHechura and roundingDirectionHechura to PriceList
ALTER TABLE "PriceList"
  ADD COLUMN "roundingModeHechura"      "RoundingMode"      NOT NULL DEFAULT 'NONE',
  ADD COLUMN "roundingDirectionHechura" "RoundingDirection" NOT NULL DEFAULT 'NEAREST';
