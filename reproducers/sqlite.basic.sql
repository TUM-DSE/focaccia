-- Create a new table
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  age INTEGER,
  email TEXT UNIQUE
);

-- Insert some rows
INSERT INTO users (name, age, email)
VALUES
  ('Alice', 30, 'alice@example.com'),
  ('Bob', 25, 'bob@example.com'),
  ('Charlie', 35, 'charlie@example.com');

-- Query all rows
SELECT * FROM users;

-- Filter results
SELECT name, age FROM users WHERE age > 28;

-- Update a row
UPDATE users SET age = 31 WHERE name = 'Alice';

-- Delete a row
DELETE FROM users WHERE name = 'Bob';

-- Add a new column
ALTER TABLE users ADD COLUMN city TEXT;

-- Update new column values
UPDATE users SET city = 'Berlin' WHERE name = 'Alice';
UPDATE users SET city = 'Paris' WHERE name = 'Charlie';

-- Aggregate query
SELECT city, COUNT(*) AS user_count FROM users GROUP BY city;

-- Create an index for faster lookups
CREATE INDEX idx_users_email ON users(email);

-- Show table schema
.schema users;

-- Export query results to CSV (in sqlite3 CLI)
.headers on
.mode csv
.output users.csv
SELECT * FROM users;
.output stdout

