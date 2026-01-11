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
INSERT INTO users VALUES (1, 'Mario', 'password123', 'normal');
INSERT INTO users VALUES (2, 'Luigi', 'maint2024', 'normal');
INSERT INTO users VALUES (3, 'Giorgio', 'wrench!', 'normal');
INSERT INTO users VALUES (4, 'superman', 'supervisor123', 'technician');
INSERT INTO users VALUES (5, 'admin', 'forzatoro', 'technician');

INSERT INTO devices VALUES (1, 'Pump-01', 0, NULL);
INSERT INTO devices VALUES (2, 'Pump-02', 0, NULL);
INSERT INTO devices VALUES (3, 'Valve-01', 0, NULL);
INSERT INTO devices VALUES (4, 'Valve-02', 0, NULL);
INSERT INTO devices VALUES (5, 'Conveyor-01', 0, NULL);
INSERT INTO devices VALUES (6, 'Boiler-01', 0, NULL);
INSERT INTO devices VALUES (7, 'Compressor-01', 0, NULL);