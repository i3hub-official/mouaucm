-- This script only contains the table creation statements and does not fully represent the table in the database. It's still missing: indices, triggers. Do not use it as a backup.

-- Table Definition
CREATE TABLE "public"."admins" (
    "id" text NOT NULL,
    "email" text NOT NULL,
    "password" text NOT NULL,
    "name" text NOT NULL,
    "role" text NOT NULL DEFAULT 'ADMIN'::text,
    "isActive" bool NOT NULL DEFAULT true,
    "createdAt" timestamp NOT NULL DEFAULT now(),
    PRIMARY KEY ("id")
);

INSERT INTO "public"."admins" ("id", "email", "password", "name", "role", "isActive", "createdAt") VALUES
('818c5ded-a020-407b-be1d-16bdeaae3768', 'ogwogp@gmail.com', '$2b$12$pETm9gr3.34tNFR64Ugy1upngL27fGpSm53765pMH3eO.oeuWSYBm', 'Ogwo GP', 'ADMIN', 't', '2025-09-15 21:24:49.273');
