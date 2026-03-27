-- AlterTable
ALTER TABLE "CatalogItem" ADD COLUMN     "isSystem" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "PaymentMethod" ADD COLUMN     "isSystem" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "ShippingCarrier" ADD COLUMN     "isSystem" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "Tax" ADD COLUMN     "isSystem" BOOLEAN NOT NULL DEFAULT false;
