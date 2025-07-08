library(DBI)
library(RSQLite)
library(readxl)

informe_ciberataques_db <- function(){
  excel_path <-  "C:/Users/nicol/OneDrive/Documentos/GitHub/security-dashboard-shiny/Informe_Ciberataques_Q1_2025_con_estado.xlsx" 
  data <- read_excel(excel_path)

  names(data) <- c("Id", "Categoría", "Descripción", "Impacto", "FechaDetección", "EstadoResolución")

  db_path <- "C:/Users/nicol/OneDrive/Documentos/GitHub/security-dashboard-shiny/cyberattacks.sqlite"
  conn <- dbConnect(RSQLite::SQLite(), db_path)

  data$FechaDetección <- format(as.Date(data$FechaDetección), "%Y-%m-%d")

  dbExecute(conn, "
	CREATE TABLE IF NOT EXISTS cyberattacks (
	  Id INTEGER PRIMARY KEY, 
	  Categoría TEXT,
	  Descripción TEXT,
	  Impacto TEXT,
	  FechaDetección TEXT,
	  EstadoResolución TEXT
	)
  ")

  dbWriteTable(conn, "cyberattacks", data, append=TRUE, row.names=FALSE)
  dbDisconnect(conn)
}

informe_ciberataques_db()