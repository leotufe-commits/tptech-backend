-- Formalizar relación Seller.userId → User.id
-- Un usuario puede ser vendedor como máximo una vez (unique en userId)
-- Si el usuario es eliminado, se desvincula el vendedor (SetNull)

-- CreateIndex: unique constraint en Seller.userId
CREATE UNIQUE INDEX "Seller_userId_key" ON "Seller"("userId");

-- AddForeignKey
ALTER TABLE "Seller" ADD CONSTRAINT "Seller_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
