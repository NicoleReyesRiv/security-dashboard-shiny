library(shiny)
library(shinydashboard)
library(DT)
library(shinymanager)
library(DBI)
library(RSQLite)
library(keyring)

print("empezando")
credentials <- data.frame(
	user = c("admin", "client"),
	password = c("admin123","client123"),
	
	#password will automatically be hashed
	
	admin = c(TRUE, FALSE),
	stringAsFactors = FALSE
)

#print("pasado")

#Recuperar la passphrase de forma segura
passphrase <- key_get("R-shinymanager-key", "nicol")
sqlite_path <- "database.sqlite"
if (!file.exists(sqlite_path)) {
  create_db(
    credentials_data = credentials,
    sqlite_path = sqlite_path,
    passphrase = passphrase
  )
}

ui <- secure_app(
	dashboardPage(
	dashboardHeader(title = "Security Dashboard"),
	dashboardSidebar(
		sidebarMenuOutput("sidebar")
	),
	dashboardBody(
		tabItems(
			#panel principal
			tabItem(
				tabName= "dashboard",
				fluidRow(
					box(title="Accesos recientes", width=6, status="primary",tableOutput("access_table")),
					box(title="Intentos de acceso fallidos", width=6, status="danger", plotOutput("failed_attempts"))
				),
				fluidRow(
					box(title="Alertas recientes", width=12, status="warning", tableOutput("alerts"))
				)
			),
			#panel de seguridad
			tabItem(
				tabName="security",
				fluidRow(
					box(title="Intentos de ataque detectados", width=6, status="danger", tableOutput("attack_table")),
					box(title="IPs sospechosas", width=6, status="warning", tableOutput("ip_blacklist"))
				),
				fluidRow(
					box(title="Mapa de amenazas", width=12, status="info", plotOutput("threat_map"))
				)
			),
			#panel de estado del sistema
			tabItem(
				tabName="system",
				fluidRow(
					box(title="Uso de CPU", width=6, status="info", plotOutput("cpu_usage")),
					box(title="Uso de RAM", width=6, status="info", plotOutput("ram_usage"))
				),
				fluidRow(
					box(title="Estado de los servidores", width=12, status="success", tableOutput("server_status"))
				)
			),
			#panel de logs
			tabItem(
				tabName="logs",
				fluidRow(
					box(title="Registro de accesos", width=12, status="primary", DT::DTOutput("access_logs"))
				)
			)
		)
	)),
	enable_admin = TRUE
)

server <- function(input,output, session){
		
	res_auth <- secure_server(
		check_credentials = check_credentials(
		  sqlite_path, 
		  passphrase = passphrase
		)
	)


	output$auth_output <- renderPrint({
		auth_data <- reactiveValuesToList(res_auth)

		print("Contenido de res_auth:")
    		print(auth_data)  # Ver qué tiene antes de usarlo
		
		if (length(auth_data) == 0){
			return("No hay datos de autenticación disponibles")
		}
		auth_data
	})

	logs_data <- reactive({
		conn <- dbConnect(RSQLite::SQLite(), "security_logs.db")
		logs <- tryCatch({
			dbGetQuery(conn, "SELECT * FROM logs ORDER BY timestamp DESC") #de más reciente a más antiguo
		}, error = function(e) data.frame(Mensaje = "No hay registros disponibles"))
		
		dbDisconnect(conn)

		if (nrow(logs) == 0) {
			return(data.frame(Mensaje = "No hay datos disponibles"))
    		}
		return(logs)
	})

	output$access_logs <- renderDT({
		datatable(logs_data(), options = list(pageLength=5))
	})
	
	output$sidebar <- renderMenu({

		if (is.null(res_auth$user)) {
        		print("Usuario no autenticado, sidebar básico cargado")
        		return(sidebarMenu(
            		menuItem("Panel principal", tabName = "dashboard", icon = icon("tachometer-alt")),
            		menuItem("Logs", tabName = "logs", icon = icon("file-alt"))
        		))
    		}
    		role <- tryCatch(res_auth$user, error = function(e) NULL)
    
    		sidebar_items <- list(
        		menuItem("Panel principal", tabName = "dashboard", icon = icon("tachometer-alt")),
        		menuItem("Logs", tabName = "logs", icon = icon("file-alt"))
    		)
    
    		if (!is.null(role) && role == "admin") {
        		sidebar_items <- append(sidebar_items, list(
            		menuItem("Seguridad", tabName = "security", icon = icon("shield-alt")),
            		menuItem("Estado del sistema", tabName = "system", icon = icon("server"))
        		))
    		}
    
    		do.call(sidebarMenu, sidebar_items)
})

}

#options(error = recover)
shinyApp(ui, server)