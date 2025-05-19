library(shiny)
library(shinydashboard)
library(DT)
library(shinymanager)
library(keyring)
library(jsonlite)
library(scrypt)
library(DBI)
library(readxl)

### rutas del proyecto
base <- "C:/Users/nicol/OneDrive/Documentos/GitHub/security-dashboard-shiny"
ruta_usuarios_sqlite <- file.path(base, "users.sqlite")
ruta_logs_sqlite <- file.path(base, "logs.sqlite")
ruta_excel_ataques <- file.path(base, "Informe_Ciberataques_Q1_2025_con_estado.xlsx")



db_connection <- dbConnect(RSQLite::SQLite(), ruta_logs_sqlite)


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
						box(title="Distribución de ataques detectados por categoría", width=8, status="info", plotOutput("attacks_clasification"))					
	  				),
					fluidRow(
						box(
							title="Intentos de ataques detectados", 
							width=12, 
							status="warning",
							fluidRow(
								column(3,infoBoxOutput("attacks_total")),
								column(9,plotOutput("impact_graph"))
							)					
						)
						
    					
  					)
				),
				tabItem(
  					tabName="security",
  					fluidRow(
    						box(title="Intentos de ataques detectados", width=12, status="warning", DT::DTOutput("attack_table")),
    						#box(title="IPs sospechosas", width=6, status="warning", tableOutput("ip_blacklist"))
  					),
					fluidRow(
    						box(title="Gestión de incidentes", width=12, status="danger", plotOutput("attack_category_state"))
  					),
					fluidRow(
    						box(title="Evolución temporal de los ataques detectados", width=12, status="info", plotOutput("attack_timeline"))
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
  					),
					fluidRow(
						box(title="Accesos recientes", width=6, status="success", plotOutput("access_summary")),
   	 					box(title="Intentos de acceso fallidos", width=6, status="danger", plotOutput("failed_attempts")),
					
	  				)

				)
			)
		)
	), enable_admin = TRUE
)


server <- function(input, output, session){

	attacks_data <- reactive({
		readxl::read_excel(ruta_excel_ataques)
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
			summary <- table(factor(logs$status, levels = c("exitoso", "fallido")))
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

	log_access <- function(user, status, session){
#		ip <- tryCatch(session$clientData$REMOTE_ADDR, error = function(e) NA)
#		if (is.null(ip) || length(ip) != 1 || is.na(ip) || ip == ""){
#    			ip <- "Desconocido"
#  		}
		if (is.null(user) || length(user) != 1 || is.na(user) || user == ""){
    			user <- "Desconocido"
  		}
		if (is.null(status) || length(status) != 1 || is.na(status) || status == ""){
    			status <- "Desconocido"
  		}

		timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")


		if (status == "fallido"){
			dbExecute(db_connection,
				"INSERT OR REPLACE INTO login_limit (user, attempts, last_attempt) 
				VALUES (?, COALESCE((SELECT attempts FROM login_limit WHERE user = ?), 0) + 1, ?)",
				params = list(user,user, timestamp))
		}else {
			dbExecute(db_connection,
				"INSERT OR REPLACE INTO login_limit (user, attempts, last_attempt) 
				VALUES (?, 0, NULL)",
				params = list(user))

		}
		dbExecute(db_connection, "INSERT INTO logs (timestamp,user,status,country)VALUES (?,?,?,?)", params= list(timestamp,user,status,"Desconocido"))
		
	}
	

	attempt_limit <- 5
	time_limit <- 120 #seconds

	secure_credentials <- function(users_db_path, passphrase){
		function(user, password, session){
			ip <- tryCatch(session$clientData$REMOTE_ADDR, error = function(e) NA)

			check_attempts <- dbGetQuery(db_connection, 
			"SELECT attempts, last_attempt FROM login_limit WHERE user = ?", params = list(user))

			if(nrow(check_attempts) > 0){
				last <- as.POSIXct(check_attempts$last_attempt, format="%Y-%m-%d %H:%M:%S")
				now <- Sys.time()

				
				if (check_attempts$attempts >= attempt_limit){
					if(!is.na(last) && difftime(now, last, units = "secs") < time_limit){
						showNotification("Demasiados intentos fallidos. Inténtalo de nuevo más tarde.", type = "error")
					}
				}

				dbExecute(db_connection, "UPDATE login_limit SET attempts = attempts + 1, last_attempt = ? WHERE user = ?",
				params = list(format(now, "%Y-%m-%d %H:%M:%S"),user))
			
			}else{
				dbExecute(db_connection, "INSERT INTO login_limit (user, attempts, last_attempt) VALUES (?, 1, ?)",
				params = list(user, format(Sys.time(), "%Y-%m-%d %H:%M:%S")))
			}

			creds <- shinymanager::check_credentials(
				db= users_db_path,
				passphrase = passphrase
			)
			result <- creds(user, password)

			if(result$result){
				user_logged <- if(!is.null(result) && "user" %in% names(result)){
					result$user
				}else{ 
					user
				}
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
        		ruta_usuarios_sqlite,
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
			menuItem("Panel principal", tabName="dashboard", icon=icon("tachometer-alt"))
		)
		}
	})

	output$access_logs <- DT::renderDT({
		logs_data <- get_logs_data()
		DT::datatable(logs_data, options = list(pageLength = 10, autoWidth = TRUE))
	})
	
	
	output$attacks_total <- renderInfoBox({
		infoBox(
			value= attacks_total_number(),
			title = "Número total",
			subtitle="Nº total",
			icon = icon("list"),
			color = "red",
			
		)
	})

	output$impact_graph <- renderPlot({
		barplot(
			impact_in_progress(),
			col = c("red","orange","yellow","green"),
			main = "Ataques en curso por nivel de impacto",
			ylab = "Número de ataques",
			xlab= "Nivel de impacto",
			las=1
		)
	})

	output$attacks_clasification <- renderPlot({
		df <- readxl::read_excel(ruta_excel_ataques)
		df_valid <- df[!tolower(df$`Estado de Resolución`) %in% "descartado",]
		counts <- table(df_valid$Categoría, df_valid$`Estado de Resolución`)
		counts_df <- as.data.frame.matrix(counts)

		counts_df <- counts_df[order(rowSums(counts_df)), , drop=FALSE]
		
		total_max <- max(rowSums(counts_df))

		par(mar = c(5, 20, 4, 2)) #ampliar margen izquierdo para los nombres largos
		
		barplot(
			height = t(as.matrix(counts_df[, c("cerrado", "en curso")])),
			beside = FALSE,
			horiz = TRUE,
			col = c("green","orange"),
			legend.text = c("Cerrado","En curso"),
			args.legend = list(x = "bottomright", bty = "n"),
			main="Ataques detectados por categoría",
			xlab = "Número de ataques",
			las = 1,
			xaxt = "n"
		)
		axis(1, at = 0:ceiling(total_max), labels=0:ceiling(total_max))
	})

	output$attack_table <- DT::renderDT({
		df <- readxl::read_excel(ruta_excel_ataques)
		DT::datatable(
			df, options = list(pageLength=10, autoWidth=TRUE, scrollX=TRUE), filter="top", rownames=FALSE
		)
	})

	output$attack_category_state <- renderPlot({
		df <- readxl::read_excel(ruta_excel_ataques)
		counts <- table(df$`Categoría`, df$`Estado de Resolución`)
		counts_df <- as.data.frame.matrix(counts)
		counts_df <- counts_df[order(rowSums(counts_df)), , drop=FALSE]

		par(mar=c(5,20,4,2))
		barplot(
			height = t(as.matrix(counts_df)),
			beside = FALSE, horiz=TRUE, col= c("green","orange","grey"),
			legend.text=colnames(counts_df), args.legend=list(x="bottomright", bty="n"),
			xlab="Número de ataques", main="Ataques por categoría y estado de resolución", las=1
		)
	})

	output$attack_timeline <- renderPlot({
		df <- readxl::read_excel(ruta_excel_ataques)
		df$Fecha <- as.Date(df$`Fecha de Detección`)
		df <- df[!tolower(df$`Estado de Resolución`) %in% "descartado",]
		
		timeline <- as.data.frame(table(df$Fecha))
		names(timeline) <- c("Fecha","Frecuencia")
		timeline$Fecha <- as.Date(timeline$Fecha)
		
		plot(
			timeline$Fecha, timeline$Frecuencia,
			type="l", lwd=2, col="blue", main="Ataques detectados por día",
			xlab="Fecha", ylab="Número de ataques", xaxt="n"
		)
		axis.Date(1, at = seq(min(timeline$Fecha), max(timeline$Fecha), by="week"), format = "%d %b")

		#axis(2,at=seq(0, max(timeline$Frecuencia), by=1), labels=seq(0, max(timeline$Frecuencia), by=1))
		points(timeline$Fecha, timeline$Frecuencia, pch=19, col="blue")
		
	})

}

shinyApp(ui,server)
