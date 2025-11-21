PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS faculty;
DROP TABLE IF EXISTS labs;
DROP TABLE IF EXISTS users;

CREATE TABLE labs (
  lab_id INTEGER PRIMARY KEY AUTOINCREMENT,
  lab_name TEXT NOT NULL UNIQUE,
  location TEXT,
  capacity INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE faculty (
  faculty_id INTEGER PRIMARY KEY AUTOINCREMENT,
  faculty_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  department TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE devices (
  device_id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_name TEXT NOT NULL,
  device_type TEXT NOT NULL,
  configuration TEXT,
  status TEXT DEFAULT 'active',
  lab_id INTEGER,
  faculty_id INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (lab_id) REFERENCES labs (lab_id) ON DELETE SET NULL,
  FOREIGN KEY (faculty_id) REFERENCES faculty (faculty_id) ON DELETE SET NULL
);

CREATE TABLE users (
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password TEXT, -- Hashed password for email/password login
  google_id TEXT UNIQUE, -- Google ID for Google Auth
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);