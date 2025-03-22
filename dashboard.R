library(shiny)
library(shinydashboard)
library(DT)
library(shinymanager)
library(keyring)


db_connection <- dbConnect(RSQLite::SQLite(), "C:/Users/nicol/OneDrive/Documentos/proyectos R/TFG/v3/logs.sqlite")


ui <- secure_app(

	dashboardPage(
		dashboardHeader(title="Security Dashboard"),
		dashboardSidebar(
			sidebarMenuOutput("sidebar")
		),
		dashboardBody(
			tabItems(
				tabItem(
  					tabName= "dashboard",
  					fluidRow(
						box(title="Accesos recientes", width=6, status="primary", tableOutput("access_table")),
   	 					box(title="Intentos de acceso fallidos", width=6, status="danger", plotOutput("failed_attempts")),
					
	  				),
					fluidRow(
    						box(title="Alertas recientes", width=12, status="warning", tableOutput("alerts"))
  					)
				),
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

				# Panel de Logs
				tabItem(
  					tabName="logs",
  					fluidRow(
    						box(title="Registro de accesos", width=12, status="primary", DT::DTOutput("access_logs"))
  					)

				)
			)
		)
	), enable_admin = TRUE
)


server <- function(input, output, session){
	
	res_auth <- secure_server(
    		check_credentials = check_credentials(
        		"C:/Users/nicol/OneDrive/Documentos/proyectos R/TFG/v3/users.sqlite",
        		passphrase = key_get("R-shinymanager-key", "nicol")
        		# passphrase = "passphrase_wihtout_keyring"
		)
    	)

	user_role <- reactive ({
		res_auth$admin
	})
	
	output$auth_output <- renderPrint({
    		reactiveValuesToList(res_auth)
  	})
	
	get_logs_data <- function(){
		
		logs_data <- dbGetQuery(db_connection, "SELECT * FROM logs ORDER BY timestamp DESC")
		return(logs_data)
		dbDisconnect(db_connection)

	}


	output$sidebar <- renderMenu({
		if (user_role()) {
  		sidebarMenu(
    			menuItem("Panel principal", tabName="dashboard", icon=icon("tachometer-alt")),
			menuItem("Seguridad", tabName="security", icon=icon("shield-alt")),
        		menuItem("Estado del sistema", tabName="system", icon=icon("server")),
			menuItem("Logs", tabName="logs", icon=icon("file-alt"))
		)
		}else{
		sidebarMenu(
			menuItem("Panel principal", tabName="dashboard", icon=icon("tachometer-alt")),
			menuItem("Logs", tabName="logs", icon=icon("file-alt"))

		)
		}
	})

	output$access_logs <- DT::renderDT({
		logs_data <- get_logs_data()
		DT::datatable(logs_data, options = list(pageLength = 10, autoWidth = TRUE))
	})
	
	

}

shinyApp(ui,server)



