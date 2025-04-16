library(shiny)
library(shinydashboard)
library(DT)
library(shinymanager)
library(keyring)
library(jsonlite)
library(scrypt)
library(DBI)
library(readxl)

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
						box(title="Accesos recientes", width=6, status="success", plotOutput("access_summary")),
   	 					box(title="Intentos de acceso fallidos", width=6, status="danger", plotOutput("failed_attempts")),
					
	  				),
					fluidRow(
    						box(title="Intentos de ataques detectados", width=12, status="warning",
		 				fluidRow(
							column(4, valueBoxOutput("attacks_total")),
							column(8, plotOutput("impact_graph")))
						)
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

	attacks_data <- reactive({
		readxl::read_excel("C:/Users/nicol/OneDrive/Documentos/proyectos R/TFG/v3/Informe_Ciberataques_Q1_2025_con_estado.xlsx")
	})

	attacks_total_number <- reactive({
		df <- attacks_data()
		nrow(df[!tolower(df$`Estado de Resolución`) %in% "descartado",])
	})

	impact_in_progress <- reactive({
		df <- attacks_data()
		in_progress <- df[tolower(df$`Estado de Resolución`) == "en curso",]
		table(in_progress$`Nivel de Impacto`)
	})

	output$access_summary <- renderPlot ({
		logs <- get_logs_data()

		if (nrow(logs)==0){
			plot.new()
			title("No hay datos de accesos")
		}else{
			summary <- table(logs$status)
			barplot(
				summary, 
				col = c("green","red")[match(names(summary),c("exitoso","fallido"))],
				main = "Resumen accesos recientes",
				ylab="Número de accesos",
				names.arg = c("Exitosos","Fallidos"),
				ylim = c(0, max(summary)+1)
			)
		}
	})

	output$failed_attempts <- renderPlot({
		logs <- get_logs_data()
		failed <- subset(logs, status=="fallido")
		
		if(nrow(failed) == 0){
			plot.new()
			title("No hay intentos fallidos registrados")
		}else{
			counts <- table(failed$user)
			barplot(
				sort(counts,decreasing=TRUE),
				col = "red",
				main = "Intentos de acceso fallido por usuario",
				xlab = "Usuario",
				ylab = "Número de intentos fallidos",
				las = 2
			)
		}
	})

	log_access <- function(user,status,session){
		ip <- tryCatch(session$clientData$REMOTE_ADDR, error= function(e) NA)
		if (is.null(ip) || length(ip) != 1 || is.na(ip) || ip == ""){
    			ip <- "Desconocido"
  		}
		if (is.null(user) || length(user) != 1 || is.na(user) || user == ""){
    			user <- "Desconocido"
  		}
		if (is.null(status) || length(status) != 1 || is.na(status) || status == ""){
    			status <- "Desconocido"
  		}

		timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
		DBI::dbExecute(db_connection, "INSERT INTO logs (timestamp,user,ip,status,country)VALUES (?,?,?,?,?)", params= list(timestamp,user,ip,status,"Desconocido"))
	}
	
	secure_credentials <- function(users_db_path, passphrase){
		function(user,password){
				creds <- shinymanager::check_credentials(
					db= users_db_path,
					passphrase = passphrase
				)
				result <- creds(user,password)

				if(result$result){
					user_logged <- if(!is.null(result) && "user"%in% names(result)) result$user else user
					log_access(user=user_logged, status="exitoso",session=shiny::getDefaultReactiveDomain())
					return(result)
				}else{
					log_access(user=user, status="fallido",session=shiny::getDefaultReactiveDomain())
					return(NULL)
				}
		}
	}
	
	res_auth <- secure_server(
    		check_credentials = secure_credentials(
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
	
	
	output$attacks_total <- renderValueBox({
		valueBox(
			value= attacks_total_number(),
			subtitle = "Número total de ataques detectados Q1 2025",
			icon = icon("shield-virus"),
			color = "red"
		)
	})

	output$impact_graph <- renderPlot({
		barplot(
			impact_in_progress(),
			col = c("red","orange","yellow","green"),
			main = "Ataques en curso por nivel de impacto",
			ylab = "Número de ataques",
			xlab= "Nivel de impacto"
			las=1
		)
	})

}

shinyApp(ui,server)
