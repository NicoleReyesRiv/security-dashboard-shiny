library(DBI)
library(RSQLite)

logs_db <- function(){
  db_path <- "C:/Users/nicol/OneDrive/Documentos/GitHub/security-dashboard-shiny/logs.sqlite"
  conn <- dbConnect(RSQLite::SQLite(), db_path)

  dbExecute(conn, "
	CREATE TABLE IF NOT EXISTS logs (
	  timestamp TEXT, 
	  user TEXT,
	  status TEXT,
	  country TEXT
	)
  ")

#  dbExecute(conn, "
#  		INSERT INTO logs (timestamp, user, status, country) VALUES
#  		('2024-02-22 10:30:00', 'admin', 'exitoso', 'España'),
#  		('2024-02-22 10:32:15', 'admin', 'fallido', 'EE.UU.'),
#  		('2024-02-22 10:35:00', 'viewer', 'exitoso', 'Alemania'),
#  		('2024-02-22 10:40:00', 'viewer', 'exitoso', 'España'),
#  		('2024-02-22 10:45:22', 'admin', 'fallido', 'Reino Unido')
#	")
  dbExecute(conn, "
    CREATE TABLE IF NOT EXISTS login_limit (
	  user TEXT PRIMARY KEY,
	  attempts INTEGER DEFAULT 0
	)
  ")

  dbDisconnect(conn)
}

logs_db()