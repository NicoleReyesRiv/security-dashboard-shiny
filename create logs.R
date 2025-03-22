library(DBI)
library(RSQLite)

logs_db <- function(){
	db_path <- "C:/Users/nicol/OneDrive/Documentos/proyectos R/TFG/v3/logs.sqlite"
	
	conn <- dbConnect(RSQLite::SQLite(), db_path)

	dbExecute(conn, "
		CREATE TABLE IF NOT EXISTS logs (
			timestamp TEXT, 
			user TEXT,
			ip TEXT,
			status TEXT,
			country TEXT
		)

	") 	
	dbExecute(conn, "
  		INSERT INTO logs (timestamp, user, ip, status, country) VALUES
  		('2024-02-22 10:30:00', 'admin', '192.168.1.1', 'exitoso', 'España'),
  		('2024-02-22 10:32:15', 'admin', '203.0.113.5', 'fallido', 'EE.UU.'),
  		('2024-02-22 10:35:00', 'tech', '45.67.89.10', 'exitoso', 'Alemania'),
  		('2024-02-22 10:40:00', 'client', '192.168.1.2', 'exitoso', 'España'),
  		('2024-02-22 10:45:22', 'admin', '185.76.9.34', 'fallido', 'Reino Unido')
	")


	dbDisconnect(conn)
}

logs_db()