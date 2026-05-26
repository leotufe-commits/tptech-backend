-- AlterTable
ALTER TABLE "DocumentTemplate" ADD COLUMN     "emailMessageTemplate" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "emailSubjectTemplate" TEXT NOT NULL DEFAULT '';
