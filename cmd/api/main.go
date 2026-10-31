// Punto de entrada del backend de SecurityBank.
package main

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"time"

	"github.com/joho/godotenv"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"securityBank_server/internal/config"
	"securityBank_server/internal/database"
	"securityBank_server/internal/handlers"
	"securityBank_server/internal/models"
	"securityBank_server/internal/repositories"
	"securityBank_server/internal/services"
	"securityBank_server/middleware"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No se ha encontrado el archivo .env")
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("error de configuración: %v", err)
	}

	// Claves de cifrado en reposo. Se exige una clave distinta para los datos
	// sensibles (DNI/IBAN) y para TOTP. Si alguna no es válida, no se arranca
	// con una clave por defecto.
	dataKey, err := services.DecodeEncryptionKey(cfg.DataEncryptionKey)
	if err != nil {
		log.Fatalf("error configurando clave de cifrado de datos sensibles: %v", err)
	}
	if err := models.SetDataEncryptionKey(dataKey); err != nil {
		log.Fatalf("error configurando clave de cifrado de datos sensibles: %v", err)
	}

	totpKey, err := services.DecodeTOTPEncryptionKey(cfg.TOTPEncryptionKey)
	if err != nil {
		log.Fatalf("error configurando clave de cifrado TOTP: %v", err)
	}
	if subtle.ConstantTimeCompare(dataKey, totpKey) == 1 {
		log.Fatal("DATA_ENCRYPTION_KEY y TOTP_ENCRYPTION_KEY deben ser claves distintas")
	}

	serverPrivateKey, err := services.LoadOrCreateServerKey(cfg.ServerKeyPath)
	if err != nil {
		log.Fatalf("error cargando la identidad del servidor: %v", err)
	}
	serverIdentity, err := services.ExportServerPublicIdentity(serverPrivateKey)
	if err != nil {
		log.Fatalf("error exportando la identidad del servidor: %v", err)
	}
	// La huella permite fijar la identidad del servidor en el frontend (SERVER_KEY_FINGERPRINT).
	log.Printf("identidad asimétrica del servidor preparada (huella SHA-256: %s)", serverIdentity.FingerprintSHA256)

	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("error de base de datos: %v", err)
	}
	log.Println("conexión con PostgreSQL establecida")

	// Avisa si falta alguna tabla (por ejemplo, si no se han aplicado las migraciones).
	// No se crean tablas: el esquema solo se gestiona con las migraciones SQL.
	missing, err := database.MissingTables(context.Background(), db)
	switch {
	case err != nil:
		log.Printf("AVISO: no se pudo comprobar el esquema: %v", err)
	case len(missing) > 0:
		log.Printf("AVISO: faltan tablas en la base de datos: %v. Aplica las migraciones: docker compose run --rm migrate up (ver README).", missing)
	default:
		log.Println("esquema de la base de datos comprobado: todas las tablas existen")
	}

	// La migración 000011 deja las columnas BYTEA, pero no puede cifrar su
	// contenido porque no conoce DATA_ENCRYPTION_KEY. Completamos el cifrado de
	// los DNI/IBAN heredados antes de atender peticiones.
	if len(missing) == 0 {
		backfill, err := database.BackfillSensitiveData(context.Background(), db)
		if err != nil {
			log.Fatalf("error cifrando los datos sensibles heredados: %v", err)
		}
		if backfill.Users > 0 || backfill.Accounts > 0 {
			log.Printf(
				"datos sensibles heredados cifrados: %d DNI y %d IBAN",
				backfill.Users,
				backfill.Accounts,
			)
		}

		// Comprueba que la clave configurada descifra los datos ya existentes.
		// Si es incorrecta, preferimos no arrancar antes que fallar en cada
		// consulta con errores 500.
		if err := database.VerifySensitiveDataKey(context.Background(), db); err != nil {
			log.Fatalf("error verificando la clave de cifrado de datos sensibles: %v", err)
		}
	}

	router := gin.Default()

	// No hay ningún proxy delante del backend: no confiamos en cabeceras
	// como X-Forwarded-For para obtener la IP del cliente.
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Fatalf("error configurando proxies de confianza: %v", err)
	}

	// CORS: solo el frontend de desarrollo puede llamar a la API desde el navegador.
	router.Use(cors.New(cors.Config{
		AllowOrigins: []string{cfg.CORSOrigin},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Origin", "Content-Type", "Authorization", "Idempotency-Key"},
		MaxAge:       12 * time.Hour,
	}))

	api := router.Group("/api")
	api.Use(middleware.APISecurityHeaders())
	api.GET("/health", handlers.Health)
	api.GET("/health/db", handlers.HealthDB(db))
	api.GET("/server/public-key", handlers.ServerPublicIdentity(serverPrivateKey))

	userRepository := repositories.NewUserRepository(db)
	userService := services.NewUserService(userRepository, serverPrivateKey)

	accountRepository := repositories.NewAccountRepository(db)
	accountService := services.NewAccountService(accountRepository, serverPrivateKey)
	challengeService := services.NewAuthChallengeService()

	transactionRepository := repositories.NewTransactionRepository(db, services.DeriveHMACKey(serverPrivateKey))
	transactionService := services.NewTransactionService(transactionRepository, accountRepository, serverPrivateKey)

	documentRepository := repositories.NewDocumentRepository(db, services.DefaultDocumentQuota)
	documentService := services.NewDocumentService(
		documentRepository,
		userRepository,
		&serverPrivateKey.PublicKey,
	)

	totpService, err := services.NewTOTPService(userRepository, totpKey)
	if err != nil {
		log.Fatalf("error creando servicio TOTP: %v", err)
	}
	totpHandler := handlers.NewTOTPHandler(totpService)

	// Login y registro
	api.POST("/login/challenge", handlers.StartLogin(userService, challengeService))
	api.POST("/login/verify", handlers.VerifyLogin(userService, challengeService, serverPrivateKey, totpService))
	api.POST("/register", handlers.Register(userService, totpService))
	api.POST("/totp/generate", totpHandler.Generate)

	// Cuentas bancarias y operaciones protegidas
	revokedTokens := services.NewRevokedTokens()
	protected := api.Group("/")
	protected.Use(middleware.AuthMiddleware(&serverPrivateKey.PublicKey, revokedTokens))
	protected.POST("/logout", handlers.Logout(revokedTokens))

	// Configuración 2FA (TOTP)
	totpRoutes := protected.Group("/totp")
	totpRoutes.GET("/status", totpHandler.Status)
	totpRoutes.POST("/setup", totpHandler.Setup)
	totpRoutes.POST("/enable", totpHandler.Enable)
	totpRoutes.POST("/verify", totpHandler.Verify)
	totpRoutes.POST("/disable", totpHandler.Disable)

	protected.GET("/accounts", handlers.FindUserAccounts(accountService))
	protected.POST("/accounts", handlers.CreateAccount(accountService))
	protected.PATCH("/accounts/:id/close", handlers.CloseAccount(accountService))
	protected.GET("/accounts/:id/ownership-certificate", handlers.CreateOwnershipCertificate(accountService))

	// Movimientos y operativa bancaria
	protected.POST("/accounts/:id/deposit", handlers.Deposit(transactionService))
	protected.POST("/accounts/:id/withdraw", handlers.Withdraw(transactionService))
	protected.POST("/accounts/:id/transfer", handlers.Transfer(transactionService))
	protected.GET("/accounts/:id/transactions", handlers.ListTransactions(transactionService))
	protected.GET("/accounts/:id/statement", handlers.GetAccountStatement(transactionService))
	protected.GET("/transactions/:reference/receipt", handlers.GetTransactionReceipt(transactionService))

	// Documentos cifrados de extremo a extremo: 60 peticiones por minuto y usuario (ráfagas de 30)
	documents := protected.Group("/documents")
	documents.Use(middleware.UserRateLimit(60, 30))
	documents.GET("", handlers.ListDocuments(documentService))
	documents.POST("", handlers.UploadDocument(documentService))
	documents.GET("/:id", handlers.DownloadDocument(documentService))
	documents.DELETE("/:id", handlers.DeleteDocument(documentService))

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("backend escuchando en el puerto %s", cfg.Port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("error del servidor HTTP: %v", err)
	}
}
