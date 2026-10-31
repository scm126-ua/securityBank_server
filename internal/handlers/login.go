package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"securityBank_server/internal/models"
	"securityBank_server/internal/repositories"
	"securityBank_server/internal/services"
	"securityBank_server/middleware"
)

// Duración del token de sesión y de la cookie que lo transporta.
const sessionDuration = time.Hour

type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	AuthKey  string `json:"auth_key"`
	Password string `json:"password"`
}

type LoginVerificationRequest struct {
	ChallengeID string `json:"challenge_id" binding:"required"`
	Signature   string `json:"signature" binding:"required"`
	TotpCode    string `json:"totp_code"`
}

type RegisterRequest struct {
	Email            string                  `json:"email" binding:"required,email"`
	AuthKey          string                  `json:"auth_key"`
	Password         string                  `json:"password"`
	Name             string                  `json:"name" binding:"required"`
	Surname          string                  `json:"surname" binding:"required"`
	DNI              string                  `json:"dni" binding:"required"`
	PublicKey        string                  `json:"public_key" binding:"required"`
	SigningPublicKey string                  `json:"signing_public_key" binding:"required"`
	PrivateKeyBundle PrivateKeyBundleRequest `json:"private_key_bundle" binding:"required"`
	TotpSecret       string                  `json:"totp_secret"`
	TotpCode         string                  `json:"totp_code"`
}

type PrivateKeyBundleRequest struct {
	Version    int16  `json:"version" binding:"required"`
	Algorithm  string `json:"algorithm" binding:"required"`
	KDF        string `json:"kdf" binding:"required"`
	Iterations int    `json:"iterations" binding:"required"`
	Salt       string `json:"salt" binding:"required"`
	Nonce      string `json:"nonce" binding:"required"`
	Ciphertext string `json:"ciphertext" binding:"required"`
}

// Inicia un acceso después de comprobar la contraseña y entrega un desafío.
// Cada intento queda registrado en login_audit_events.
func StartLogin(
	userService *services.UserService,
	challengeService *services.AuthChallengeService,
	loginAuditRepository *repositories.LoginAuditRepository,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input LoginRequest
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Datos de login inválidos"})
			return
		}

		// Normalizamos una sola vez para que la comprobación de bloqueo, el
		// login y la auditoría usen siempre el mismo email.
		email := normalizeLoginEmail(input.Email)

		authKey := input.AuthKey
		if authKey == "" && input.Password != "" {
			hash := sha256.Sum256([]byte(input.Password))
			authKey = base64.StdEncoding.EncodeToString(hash[:])
		}
		if authKey == "" {
			recordLoginAuditOrLog(c, loginAuditRepository, email, nil, models.LoginAuditResultFailed)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Se requiere auth_key o password"})
			return
		}

		// Comprobamos si está bloqueado
		existingUser, err := userService.FindUserByEmail(c, email)

		if err == nil && rejectIfLocked(c, existingUser.LockedUntil) {
			recordLoginAuditOrLog(
				c, loginAuditRepository, email,
				&existingUser.ID, models.LoginAuditResultFailed,
			)
			return
		}

		user, err := userService.Login(c.Request.Context(), email, authKey)
		if err != nil {
			result := models.LoginAuditResultFailed
			var userID *int64
			if existingUser != nil {
				userID = &existingUser.ID
			}
			if errors.Is(err, repositories.ErrUserNotFound) {
				result = models.LoginAuditResultAccountNotFound
				userID = nil
			}
			recordLoginAuditOrLog(c, loginAuditRepository, email, userID, result)

			// Registrar el intento fallido en backend y comprobar bloqueo
			if existingUser != nil {
				updatedUser, addErr := userService.AddFailedLoginAttempt(
					c.Request.Context(), email,
				)

				if addErr == nil && updatedUser.LockedUntil != nil &&
					time.Now().Before(*updatedUser.LockedUntil) {

					remaining := int(time.Until(*updatedUser.LockedUntil).Seconds()) + 1

					c.JSON(http.StatusLocked, gin.H{
						"error":               "Correo o contraseña incorrectos. Usuario temporalmente bloqueado",
						"retry_after_seconds": remaining,
					})
					return
				}
			}

			c.JSON(http.StatusUnauthorized, gin.H{"error": "Correo o contraseña incorrectos"})
			return
		}

		privateKeyBundle, err := services.PrivateKeyBundleForUser(user)
		if errors.Is(err, services.ErrKeyMaterialUnavailable) {
			recordLoginAuditOrLog(
				c, loginAuditRepository, email,
				&user.ID, models.LoginAuditResultFailed,
			)
			c.JSON(http.StatusConflict, gin.H{"error": "El usuario no tiene claves criptográficas"})
			return
		}
		if err != nil {
			recordLoginAuditOrLog(
				c, loginAuditRepository, email,
				&user.ID, models.LoginAuditResultFailed,
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo iniciar sesión"})
			return
		}

		challengeID, challenge, expiresAt, err := challengeService.Create(user.ID)
		if err != nil {
			recordLoginAuditOrLog(
				c, loginAuditRepository, email,
				&user.ID, models.LoginAuditResultFailed,
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo generar el desafío"})
			return
		}

		// Si no se puede auditar un login correcto, no se entrega el desafío:
		// preferimos fallar antes que abrir una sesión sin rastro.
		if err := recordLoginAudit(
			c, loginAuditRepository, email,
			&user.ID, models.LoginAuditResultSuccessful,
		); err != nil {
			log.Printf("error auditando un login correcto: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "No se pudo registrar el intento de inicio de sesión",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":             "challenge_required",
			"challenge_id":       challengeID,
			"challenge":          base64.StdEncoding.EncodeToString(challenge),
			"expires_at":         expiresAt,
			"private_key_bundle": privateKeyBundle,
			"totp_required":      user.TotpEnabled,
		})
	}

}

const (
	loginAuditEmailMaxRunes     = 320
	loginAuditIPMaxRunes        = 45
	loginAuditUserAgentMaxRunes = 512
)

// normalizeLoginEmail aplica la misma normalización que el servicio de login.
func normalizeLoginEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// recordLoginAudit guarda el intento sin incluir credenciales.
func recordLoginAudit(
	c *gin.Context,
	repository *repositories.LoginAuditRepository,
	email string,
	userID *int64,
	result string,
) error {
	if repository == nil {
		return nil
	}

	return repository.Record(c.Request.Context(), &models.LoginAuditEvent{
		UserID:    userID,
		Email:     truncateRunes(email, loginAuditEmailMaxRunes),
		IPAddress: truncateRunes(c.ClientIP(), loginAuditIPMaxRunes),
		UserAgent: truncateRunes(c.Request.UserAgent(), loginAuditUserAgentMaxRunes),
		Result:    result,
	})
}

// recordLoginAuditOrLog no interrumpe la respuesta de error si la auditoría
// falla, pero deja constancia en los logs del servidor.
func recordLoginAuditOrLog(
	c *gin.Context,
	repository *repositories.LoginAuditRepository,
	email string,
	userID *int64,
	result string,
) {
	if err := recordLoginAudit(c, repository, email, userID, result); err != nil {
		log.Printf("AVISO: no se pudo auditar el intento de login: %v", err)
	}
}

// truncateRunes limita el texto al máximo de caracteres de la columna.
func truncateRunes(value string, max int) string {
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max])
}

func rejectIfLocked(c *gin.Context, lockedUntil *time.Time) bool {
	if lockedUntil == nil || !time.Now().Before(*lockedUntil) {
		return false
	}

	remaining := int(time.Until(*lockedUntil).Seconds()) + 1

	c.JSON(http.StatusLocked, gin.H{
		"status":              "error",
		"error":               "Usuario temporalmente bloqueado",
		"locked_until":        lockedUntil,
		"retry_after_seconds": remaining,
	})

	return true
}

// Verifica la firma de un desafío consumible y entrega el token de sesión.
func VerifyLogin(
	userService *services.UserService,
	challengeService *services.AuthChallengeService,
	serverPrivateKey *rsa.PrivateKey,
	totpService *services.TOTPService,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input LoginVerificationRequest
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Verificación de login inválida"})
			return
		}

		challenge, err := challengeService.Consume(input.ChallengeID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Desafío inválido o expirado"})
			return
		}

		user, err := userService.VerifyChallenge(
			c.Request.Context(),
			challenge.UserID,
			challenge.Nonce,
			input.Signature,
		)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Firma del desafío no válida"})
			return
		}

		if user.TotpEnabled {
			if input.TotpCode == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Se requiere el código de verificación 2FA"})
				return
			}

			if err := totpService.VerifyTOTP(c.Request.Context(), user.ID, input.TotpCode); err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Código 2FA incorrecto"})
				return
			}
		}

		if err := userService.ResetFailedLoginAttempts(
			c.Request.Context(),
			user.ID,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "No se pudo actualizar el estado de autenticación",
			})
			return
		}

		// Continúa con la respuesta de login exitoso.

		tokenString, err := createJWT(user.ID, serverPrivateKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo generar el token"})
			return
		}

		setSessionCookie(c, tokenString, int(sessionDuration.Seconds()))
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"user":   user,
		})
	}
}

// Cierra la sesión: revoca el token hasta su caducidad y borra la cookie.
func Logout(revokedTokens *services.RevokedTokens) gin.HandlerFunc {
	return func(c *gin.Context) {
		revokedTokens.Revoke(c.GetString("tokenID"), c.GetTime("tokenExpiresAt"))
		setSessionCookie(c, "", -1)
		c.Status(http.StatusNoContent)
	}
}

// Genera un token de sesión de una hora con un identificador para poder revocarlo.
func createJWT(userID int64, serverPrivateKey *rsa.PrivateKey) (string, error) {
	tokenID := make([]byte, 16)
	if _, err := rand.Read(tokenID); err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"user_id": userID,
		"jti":     base64.RawURLEncoding.EncodeToString(tokenID),
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(sessionDuration).Unix(),
	})

	return token.SignedString(serverPrivateKey)
}

func setSessionCookie(c *gin.Context, token string, maxAge int) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(middleware.SessionCookieName, token, maxAge, "/api", "", true, true)
}

func Register(userService *services.UserService, totpService *services.TOTPService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input RegisterRequest

		// Aqui extraemos los datos del registro y los validamos
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Datos de registro inválidos " + err.Error(),
			})
			return
		}

		var encryptedSecret []byte
		var totpEnabled bool

		// El 2FA es opcional en el registro. Si el usuario lo activa, deben
		// llegar tanto el secreto como el código, y el código debe ser válido.
		if input.TotpSecret != "" || input.TotpCode != "" {
			if input.TotpSecret == "" || input.TotpCode == "" {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Para activar 2FA se requiere tanto el secreto como el código de verificación",
				})
				return
			}

			valid, err := totpService.ValidateCode(input.TotpSecret, input.TotpCode)
			if err != nil || !valid {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "El código 2FA no es válido",
				})
				return
			}

			encSecret, err := totpService.EncryptSecret(input.TotpSecret)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Error al procesar el secreto 2FA",
				})
				return
			}
			encryptedSecret = encSecret
			totpEnabled = true
		}

		authKey := input.AuthKey
		if authKey == "" && input.Password != "" {
			hash := sha256.Sum256([]byte(input.Password))
			authKey = base64.StdEncoding.EncodeToString(hash[:])
		}
		if authKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Se requiere auth_key o password"})
			return
		}

		// Llamamos al servicio de registro
		user, account, err := userService.Register(
			c.Request.Context(),
			input.Email,
			authKey,
			input.Name,
			input.Surname,
			input.DNI,
			services.UserKeyMaterial{
				PublicKey:        input.PublicKey,
				SigningPublicKey: input.SigningPublicKey,
				PrivateKeys: services.PrivateKeyBundle{
					Version:    input.PrivateKeyBundle.Version,
					Algorithm:  input.PrivateKeyBundle.Algorithm,
					KDF:        input.PrivateKeyBundle.KDF,
					Iterations: input.PrivateKeyBundle.Iterations,
					Salt:       input.PrivateKeyBundle.Salt,
					Nonce:      input.PrivateKeyBundle.Nonce,
					Ciphertext: input.PrivateKeyBundle.Ciphertext,
				},
			},
			encryptedSecret,
			totpEnabled,
		)
		switch {
		case errors.Is(err, services.ErrInvalidEmail):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "El correo electrónico no es válido",
			})
			return
		case errors.Is(err, services.ErrInvalidAuthKey):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "La clave de autenticación no es válida",
			})
			return
		case errors.Is(err, services.ErrInvalidDNI):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "El DNI no es válido",
			})
			return
		case errors.Is(err, services.ErrInvalidKeyMaterial):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Las claves criptográficas no son válidas",
			})
			return
		case errors.Is(err, services.ErrEmailExists):
			c.JSON(http.StatusConflict, gin.H{
				"error": "El correo electrónico ya está registrado",
			})
			return
		case errors.Is(err, services.ErrDNIExists):
			c.JSON(http.StatusConflict, gin.H{
				"error": "El DNI ya está registrado",
			})
			return
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "No se pudo completar el registro",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"user":    user,
			"account": account,
		})
	}
}
