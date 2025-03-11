library(shiny)
library(shinydashboard)
library(DT)
library(shinymanager)
library(DBI)
library(RSQLite)

credentials <- data.frame(
	user = c("admin", "client"),
	password = c("admin123", "client123"), #contraseñas texto plano
	role = c("admin", "client"),
	stringsAsFactors=FALSE 
)

credentials$password <- sapply(credentials$password, sodium::password_store) #contraseñas encriptadas

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
					box(title="Intentos de acceso fallidos", width=6, status="danger", plotOutput("failed_attemps"))
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
	)
))

server <- function(input,output, session){
	res_auth <- secure_server(
		check_credentials = check_credentials(credentials)
	)
	
	user_role <- reactive({res_auth$role})

	output$auth_status <- renderPrint({reactiveValuesToList(res_auth)})

	logs_data <- reactive({
		conn <- dbConnect(RSQLite::SQLite(), "security_logs.db")
		logs <- dbGetQuery(conn, "SELECT * FROM logs ORDER BY timestamp DESC") #de más reciente a más antiguo
		dbDisconnect(conn)
		return(logs)
	})

	output$access_logs <- renderDT({
		datatable(logs_data(), options = list(pageLength=5))
	})
	
	output$sidebar <- renderMenu({
		sidebarMenu(
			menuItem("Panel principal", tabName="dashboard", icon=icon("tachometer-alt")),
			if (user_role() == "admin"){
			  list(
				menuItem("Seguridad", tabName="security",icon=icon("shield-alt")),
				menuItem("Estado del sistema", tabName="system", icon=icon("server"))
			  )
			},
			menuItem("Logs", tabName="logs", icon=icon("file-alt"))
		)
	})

}

shinyApp(ui, server)