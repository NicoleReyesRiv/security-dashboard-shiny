library(shiny)
library(shinydashboard)
library(DT)
library(shinymanager)
library(keyring)
library(jsonlite)
library(scrypt)
library(DBI)
library(readxl)
library(shinyjs)

### rutas del proyecto
base <- "C:/Users/nicol/OneDrive/Documentos/GitHub/security-dashboard-shiny"
ruta_usuarios_sqlite <- file.path(base, "users.sqlite")
ruta_logs_sqlite <- file.path(base, "logs.sqlite")
ruta_ataques_sqlite <- file.path(base, "cyberattacks.sqlite")



db_connection <- dbConnect(RSQLite::SQLite(), ruta_logs_sqlite)
db_conn <- dbConnect(RSQLite::SQLite(), ruta_usuarios_sqlite)
db_conn_attacks <- dbConnect(RSQLite::SQLite(), ruta_ataques_sqlite)

options("shinymanager.pwd_validity" = 0)


ui <- secure_app(
	tagList(useShinyjs(), tags$script(HTML("
		var idleTimer;
		function resetTimer() {
			clearTimeout(idleTimer); idleTimer = setTimeout(function(){
				Shiny.setInputValue('session_expired', true, {priority: 'event'});
			}, 10*60*1000);
		}
		$(document).on('mousemove keydown click scroll', resetTimer);
		resetTimer();
	")),
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
						box(title="Distribución de ataques detectados por categoría", width=12, status="info", plotOutput("attacks_clasification"))					
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
))

validate_password_custom <- function(pwd){
		es_valida <- all(vapply(
			X = c("[0-9]+", "[a-z]+", "[A-Z]+", "[[:punct:]]+", ".{8,}"),
			FUN = grepl, x = pwd, FUN.VALUE = logical(1)))
		if(! es_valida){
			showNotification("La contraseña debe tener al menos 8 caracteres e incluir mayúsculas, minúsculas, números y caracteres especiales.", type = "error")
		}
		return(es_valida)
}

server <- function(input, output, session){
	
	observeEvent(input$session_expired, {
		showNotification("Sesión expirada por inactividad", type = "warning")
		session$reload()
	})

	attacks_data <- reactive({
		data <- dbReadTable(db_conn_attacks, "cyberattacks")
		data
	})

	attacks_total_number <- reactive({
		df <- attacks_data()
		nrow(df[!tolower(df$`EstadoResolución`) %in% "descartado",])
	})

	impact_in_progress <- reactive({
		df <- attacks_data()
		in_progress <- df[tolower(df$`EstadoResolución`) == "en curso",]
		table(in_progress$`Impacto`)
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
			#ip <- tryCatch(session$clientData$REMOTE_ADDR, error = function(e) NA)

			check_attempts <- dbGetQuery(db_connection, 
			"SELECT attempts, last_attempt FROM login_limit WHERE user = ?", params = list(user))

			if(nrow(check_attempts) > 0){
				last <- as.POSIXct(check_attempts$last_attempt, format="%Y-%m-%d %H:%M:%S")
				now <- Sys.time()

				
				if (check_attempts$attempts >= attempt_limit){
					if(!is.na(last) && difftime(now, last, units = "secs") < time_limit){
						showNotification("Demasiados intentos fallidos. Inténtalo de nuevo más tarde.", type = "error")
						return(NULL)
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
		), validate_pwd  = validate_password_custom
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
		df <- DBI::dbReadTable(db_conn_attacks, "cyberattacks")
		df_valid <- df[!tolower(df$`EstadoResolución`) %in% "descartado",]
		counts <- table(df_valid$Categoría, df_valid$`EstadoResolución`)
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
		df <- DBI::dbReadTable(db_conn_attacks, "cyberattacks")

		DT::datatable(
			df, options = list(pageLength=10, autoWidth=TRUE, scrollX=TRUE), filter="top", rownames=FALSE
		)
	})

	output$attack_category_state <- renderPlot({
		df <- DBI::dbReadTable(db_conn_attacks, "cyberattacks")
		counts <- table(df$`Categoría`, df$`EstadoResolución`)
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
		df <- DBI::dbReadTable(db_conn_attacks, "cyberattacks")
		df$Fecha <- as.Date(df$`FechaDetección`)
		df <- df[!tolower(df$EstadoResolución) %in% "descartado",]
		
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
