library(shinymanager)
library(keyring)
library(DBI)
library(RSQLite)

credentials <- data.frame(
	user = c("admin","client"),
	password = c("123","456"),
	admin = c(TRUE,FALSE),
	stringAsFactors = FALSE
)

key_set("R-shinymanager-key", "nicol")

create_db(
	credentials_data = credentials,
	sqlite_path = "C:/Users/nicol/OneDrive/Documentos/proyectos R/TFG/v3/users.sqlite",
	passphrase = key_get("R-shinymanager-key", "nicol")
)



