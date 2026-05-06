-- CreateTable
CREATE TABLE "ArticleGroupImage" (
    "id" TEXT NOT NULL,
    "groupId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "isMain" BOOLEAN NOT NULL DEFAULT false,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ArticleGroupImage_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ArticleGroupImage_groupId_idx" ON "ArticleGroupImage"("groupId");

-- CreateIndex
CREATE INDEX "ArticleGroupImage_jewelryId_idx" ON "ArticleGroupImage"("jewelryId");

-- AddForeignKey
ALTER TABLE "ArticleGroupImage" ADD CONSTRAINT "ArticleGroupImage_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "ArticleGroup"("id") ON DELETE CASCADE ON UPDATE CASCADE;
