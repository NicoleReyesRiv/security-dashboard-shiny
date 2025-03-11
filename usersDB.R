library(DBI)
library(RSQLite)
library(sodium)  # Para encriptar contraseñas

# Conectar a la base de datos SQLite
conn <- dbConnect(RSQLite::SQLite(), "users.db")

dbExecute(conn, "
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT UNIQUE,
    password TEXT,
    role TEXT
  )
")

passwords <- sapply(c("admin123", "client123"), sodium::password_store)

dbExecute(conn, "
  INSERT OR IGNORE INTO users (user, password, role) VALUES
  ('admin', ?, 'admin'),
  ('client', ?, 'client')
", params = list(passwords[1], passwords[2]))

# Cerrar conexión
dbDisconnect(conn)

print("Base de datos de usuarios creada y usuarios insertados en users.db")
