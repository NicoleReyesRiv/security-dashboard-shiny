library(DBI)
library(RSQLite)

# Conectar a la base de datos SQLite (creará el archivo si no existe)
conn <- dbConnect(RSQLite::SQLite(), "security_logs.db")

# Crear la tabla de logs si no existe
dbExecute(conn, "
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    usuario TEXT,
    IP TEXT,
    estado TEXT,
    ubicacion TEXT
  )
")

# Insertar algunos datos de prueba en la base de datos
dbExecute(conn, "
  INSERT INTO logs (timestamp, usuario, IP, estado, ubicacion) VALUES
  ('2024-02-22 10:30:00', 'admin', '192.168.1.1', 'exitoso', 'España'),
  ('2024-02-22 10:32:15', 'admin', '203.0.113.5', 'fallido', 'EE.UU.'),
  ('2024-02-22 10:35:00', 'tech', '45.67.89.10', 'exitoso', 'Alemania'),
  ('2024-02-22 10:40:00', 'client', '192.168.1.2', 'exitoso', 'España'),
  ('2024-02-22 10:45:22', 'admin', '185.76.9.34', 'fallido', 'Reino Unido')
")

# Cerrar conexión a la base de datos
dbDisconnect(conn)

print("Base de datos creada y logs insertados en security_logs.db")
