-- ============================================================
-- CTF Lab (MySQL) — seed data for the docker-entrypoint hook.
-- Runs automatically on first container start against ctf_lab.
-- All records are synthetic; delete the container to reset.
-- ============================================================
USE ctf_lab;

CREATE TABLE users (
    id            INT PRIMARY KEY AUTO_INCREMENT,
    username      VARCHAR(64) UNIQUE NOT NULL,
    -- Deliberately weak mock credential store: unsalted MD5 of each
    -- password, so a successful blind extraction "cracks like" the real
    -- thing without touching any live system.
    password_hash CHAR(32) NOT NULL,
    email         VARCHAR(128),
    role          VARCHAR(16)
) ENGINE=InnoDB;

INSERT INTO users (username, password_hash, email, role) VALUES
    ('admin',   'f1788cf78c998d48a0ad2e76345e986e', 'admin@lab.local',   'admin'),   -- md5('S3cr3t!Adm1n')
    ('student', '482c811da5d5b4bc6d497ffa98491e38', 'student@lab.local', 'user'),    -- md5('password123')
    ('guest',   '084e0343a0486ff05530df6c705c8bb4', 'guest@lab.local',   'guest');   -- md5('guest')

CREATE TABLE secret_flag (
    id          INT PRIMARY KEY AUTO_INCREMENT,
    flag_value  VARCHAR(64) NOT NULL,
    description TEXT
) ENGINE=InnoDB;

INSERT INTO secret_flag (flag_value, description) VALUES
    ('CTF{my5ql_bl1nd_0r4cl3}',   'Row 1 - captured via boolean-blind SQLi'),
    ('CTF{inf0rm4t10n_sch3m4}',   'Row 2 - found via information_schema enumeration');

-- Teaching point baked into the grants: MYSQL_USER (labuser) is granted
-- privileges on ctf_lab ONLY. The solver therefore cannot read mysql.user
-- even though the technique would allow it — least privilege is the real
-- blast-radius control for SQL injection.
