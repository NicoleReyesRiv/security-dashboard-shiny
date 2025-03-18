library(shinymanager)
library(DBI)
library(RSQLite)

sqlite_path <- "C:/Users/nicol/OneDrive/Documentos/GitHub/security-dashboard-shiny/auth_database.sqlite"

if (file.exists(sqlite_path)) {
	file.remove(sqlite_path)
	print("Base de datos eliminada para crear una nueva")
}

conn <- dbConnect(SQLite(), sqlite_path)

credentials <- data.frame(
	user = c("admin", "client"),
	#password = Vectorize(generate_pwd)(c("admin123", "client123")),
	password = c("admin123","client123"),
	#password will automatically be hashed
	
	admin = c(TRUE, FALSE),
	stringAsFactors = FALSE
)

dbWriteTable(conn, "credentials", credentials, row.names = FALSE, overwrite = TRUE)

print("Tablas en la base de datos:")
print(dbListTables(conn))

print("Datos de la tabla credentials")
print(dbGetQuery(conn, "SELECT * FROM credentials"))

dbDisconnect(conn)

print("Base de datos creada correctamente")
