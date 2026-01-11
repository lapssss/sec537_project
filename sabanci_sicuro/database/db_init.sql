-- ----------------------------
-- USERS
-- ----------------------------
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    role TEXT
);

-- ----------------------------
-- DEVICES
-- ----------------------------
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    maintenance INTEGER,
    assigned_technician TEXT
);

-- ----------------------------
-- LOGS
-- ----------------------------
CREATE TABLE maintenance_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    user_id INTEGER,
    action TEXT,
    assigned_technician TEXT,
    timestamp TEXT
);

-- ----------------------------
-- SEED DATA
-- ----------------------------
INSERT INTO users VALUES (1, 'Mario', 'pbkdf2:sha256:600000$mnWVHobwfu2fu2zY$a09e184d516cb4b2690e10ef558d11157b288e7b0821ca0b871e469d49d5c4e4', 'normal');
INSERT INTO users VALUES (2, 'Luigi', 'pbkdf2:sha256:600000$4X3DZku5KVMLnk6Y$99438fe073224bfe7567bb81dfe0dc77e057f64832dfbfc9e63b78f8efa22583', 'normal');
INSERT INTO users VALUES (3, 'Giorgio', 'pbkdf2:sha256:600000$xN464xmcb45fA6yn$1cdd9189b85682df2013ef6a737a1e66b23db10805b19bc079f95b740ac9c55a', 'normal');
INSERT INTO users VALUES (4, 'superman', 'pbkdf2:sha256:600000$82wRPn9ZalxKH2u0$907948043aed43a79a7bd894537aabb8204a3553b6da52c0489b3ec9d1ba6db6', 'technician');
INSERT INTO users VALUES (5, 'admin', 'pbkdf2:sha256:600000$7cFJnZfz26pjeF8R$74f120c91fee002b9c6bf0f33014c62d1d55ddeab5a79cae34bf7e44c391c6ac', 'technician');

INSERT INTO devices VALUES (1, 'Pump-01', 0, NULL);
INSERT INTO devices VALUES (2, 'Pump-02', 0, NULL);
INSERT INTO devices VALUES (3, 'Valve-01', 0, NULL);
INSERT INTO devices VALUES (4, 'Valve-02', 0, NULL);
INSERT INTO devices VALUES (5, 'Conveyor-01', 0, NULL);
INSERT INTO devices VALUES (6, 'Boiler-01', 0, NULL);
INSERT INTO devices VALUES (7, 'Compressor-01', 0, NULL);