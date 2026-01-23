-- AlterTable
ALTER TABLE "Jewelry" ADD COLUMN     "pinLockEnabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "pinLockRequireOnUserSwitch" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "pinLockTimeoutSec" INTEGER NOT NULL DEFAULT 120;
