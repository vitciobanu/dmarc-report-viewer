-- One-time database + user creation. Run this as an admin user (e.g. root)
-- in MySQL Workbench or the mysql CLI.
--
--   1. Copy this file to create_db.local.sql (gitignored) and replace
--      CHANGE_ME with a password of your choice — never commit a real
--      password. Inside a MySQL '...' string, backslashes must be
--      doubled ('\\') and single quotes escaped ('''').
--   2. Run the whole script.
--   3. Put the SAME password in config.php (db.pass).
--   4. From the project root run:  php scripts/init_db.php
--
-- This script only creates the empty database and a dedicated user;
-- the tables are created by the migrations via init_db.php.

CREATE DATABASE IF NOT EXISTS dmarc
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

-- The user is created for BOTH grant hosts: MySQL treats 'localhost'
-- and '127.0.0.1' as different hosts (especially with skip-name-resolve),
-- and config.php connects over TCP to 127.0.0.1.
CREATE USER IF NOT EXISTS 'dmarc'@'localhost' IDENTIFIED BY 'CHANGE_ME';
CREATE USER IF NOT EXISTS 'dmarc'@'127.0.0.1' IDENTIFIED BY 'CHANGE_ME';

-- The app only needs to work inside its own database.
GRANT ALL PRIVILEGES ON dmarc.* TO 'dmarc'@'localhost';
GRANT ALL PRIVILEGES ON dmarc.* TO 'dmarc'@'127.0.0.1';

FLUSH PRIVILEGES;
