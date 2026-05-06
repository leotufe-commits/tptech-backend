-- Add sortOrder to ArticleAttributeDef for manual drag-and-drop ordering
ALTER TABLE "ArticleAttributeDef"
  ADD COLUMN "sortOrder" INTEGER NOT NULL DEFAULT 0;
