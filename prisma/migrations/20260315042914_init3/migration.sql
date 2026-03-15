-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'EMAIL_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'ACCOUNT_DEACTIVATED';
ALTER TYPE "AuditAction" ADD VALUE 'ACCOUNT_REACTIVATED';
ALTER TYPE "AuditAction" ADD VALUE 'EXAM_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'GRADE_RECEIVED';

-- AlterEnum
ALTER TYPE "ResourceType" ADD VALUE 'SYSTEM';
