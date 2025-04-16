library(shinymanager)
library(shinymanager)
library(keyring)
library(DBI)
library(RSQLite)

credentials <- data.frame(
	user = c("admin","viewer"),
	password = c("?O4F0W2Q^=(n","31fnE5;=}x$S"),
	admin = c(TRUE,FALSE),
	stringAsFactors = FALSE
)

key_set("R-shinymanager-key", "nicol")

create_db(
	credentials_data = credentials,
	sqlite_path = "C:/Users/nicol/OneDrive/Documentos/GitHub/security-dashboard-shiny/users.sqlite",
	passphrase = key_get("R-shinymanager-key", "nicol")
)

