-- This script only contains the table creation statements and does not fully represent the table in the database. It's still missing: indices, triggers. Do not use it as a backup.

-- Table Definition
CREATE TABLE "public"."centers" (
    "id" text NOT NULL,
    "number" text NOT NULL,
    "name" text NOT NULL,
    "address" text NOT NULL,
    "state" text NOT NULL,
    "lga" text NOT NULL,
    "isActive" bool NOT NULL DEFAULT true,
    "createdAt" timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" text NOT NULL,
    "modifiedBy" text,
    "modifiedAt" timestamp(3) NOT NULL,
    PRIMARY KEY ("id")
);

INSERT INTO "public"."centers" ("id", "number", "name", "address", "state", "lga", "isActive", "createdAt", "createdBy", "modifiedBy", "modifiedAt") VALUES
('cmfl3ouzd0005d4ebizhkonsp', '0170096', 'St Augustine Model Secondary School ', 'Uboma', 'Imo', 'Ihitte/Uboma', 't', '2025-09-15 12:28:53.593', 'ogwogp@gmail.com', 'ogwogp@gmail.com', '2025-09-15 12:28:53.593');
INSERT INTO "public"."centers" ("id", "number", "name", "address", "state", "lga", "isActive", "createdAt", "createdBy", "modifiedBy", "modifiedAt") VALUES
('cmfl3ilfx0004d4ebi8lcl8au', '0010590', 'Queen of Apostles'' Secondary Technical School ', 'Umuobiala', 'Abia', 'Isuikwuato', 't', '2025-09-15 12:24:01.294', 'ogwogp@gmail.com', 'ogwogp@gmail.com', '2025-09-15 12:32:59.212');
INSERT INTO "public"."centers" ("id", "number", "name", "address", "state", "lga", "isActive", "createdAt", "createdBy", "modifiedBy", "modifiedAt") VALUES
('cmfl35bpp0000d4eblnb6wiej', '0010402', 'Fatima Secondary Technical School ', 'Oguduasaa', 'Abia', 'Aba North', 't', '2025-09-15 12:13:42.157', 'ogwogp@gmail.com', 'ogwogp@gmail.com', '2025-09-15 12:32:59.212');
INSERT INTO "public"."centers" ("id", "number", "name", "address", "state", "lga", "isActive", "createdAt", "createdBy", "modifiedBy", "modifiedAt") VALUES
('cmfl364y80001d4eb928n94t6', '0170602', 'All Saints'' Secondary School', 'Uboma', 'Imo', 'Ihitte/Uboma', 't', '2025-09-15 12:14:20.049', 'ogwogp@gmail.com', 'ogwogp@gmail.com', '2025-09-15 12:32:59.212'),
('cmfl388fk0002d4ebfc1c3t7u', '0170201', 'Fatima Secondary School (Technical)', 'Umuakagu', 'Imo', 'Ehime-Mbano', 't', '2025-09-15 12:15:57.873', 'ogwogp@gmail.com', 'ogwogp@gmail.com', '2025-09-15 12:32:59.212'),
('cmflcolim0000c3ea9akm83u0', '0010042', 'Mater Christi Academy', 'Ngodi', 'Abia', 'Umunneochi', 't', '2025-09-15 16:40:37.871', 'ogwogp@gmail.com', 'ogwogp@gmail.com', '2025-09-15 16:40:37.871'),
('cmfl3ghh50003d4ebnx1vdzbw', '0010005', 'Madonna Secondary Technical School ', 'Ovim', 'Abia', 'Isuikwuato', 't', '2025-09-15 12:22:22.842', 'ogwogp@gmail.com', 'ogwogp@gmail.com', '2025-09-15 16:41:20.232');