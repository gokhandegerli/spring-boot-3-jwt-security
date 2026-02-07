package com.degerli.security.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AuthenticationController - Kimlik Doğrulama REST Controller
 *
 * <p><b>NE:</b> Kullanıcı kaydı (register), giriş (login) ve token yenileme (refresh)
 * endpoint'lerini sağlar.
 * Authentication işlemlerinin HTTP katmanıdır.</p>
 *
 * <p><b>NEDEN:</b>
 * - Client'ların authentication işlemlerini yapabilmesi için REST API sağlamak
 * - JWT token oluşturma ve yenileme endpoint'leri sunmak
 * - Stateless authentication mekanizması sağlamak
 * - Public endpoint'ler (authentication gerektirmez)
 * </p>
 *
 * <p><b>ENDPOINT'LER:</b>
 *
 * <b>1. POST /api/v1/auth/register</b>
 * - Yeni kullanıcı kaydı
 * - Request: RegisterRequest (firstname, lastname, email, password, role)
 * - Response: AuthenticationResponse (access token + refresh token)
 * - Public endpoint (authentication gerektirmez)
 *
 * <b>2. POST /api/v1/auth/authenticate</b>
 * - Kullanıcı girişi (login)
 * - Request: AuthenticationRequest (email, password)
 * - Response: AuthenticationResponse (access token + refresh token)
 * - Public endpoint (authentication gerektirmez)
 *
 * <b>3. POST /api/v1/auth/refresh-token</b>
 * - Token yenileme (refresh)
 * - Request: Authorization header (refresh token)
 * - Response: AuthenticationResponse (yeni access token + refresh token)
 * - Public endpoint (authentication gerektirmez)
 * </p>
 *
 * <p><b>SECURITY CONFIGURATION:</b>
 * SecurityConfiguration'da bu endpoint'ler whitelist'e eklenir:
 * <pre>
 * .requestMatchers("/api/v1/auth/**").permitAll()
 * </pre>
 * Bu sayede authentication olmadan erişilebilir.
 * </p>
 *
 * <p><b>KULLANIM ÖRNEĞİ:</b>
 * <pre>
 * // 1. REGISTER
 * POST /api/v1/auth/register
 * Content-Type: application/json
 * {
 *   "firstname": "Gokhan",
 *   "lastname": "Degerli",
 *   "email": "gokhan@mail.com",
 *   "password": "password123",
 *   "role": "USER"
 * }
 *
 * Response: 200 OK
 * {
 *   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
 *   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 * }
 *
 * // 2. LOGIN
 * POST /api/v1/auth/authenticate
 * Content-Type: application/json
 * {
 *   "email": "gokhan@mail.com",
 *   "password": "password123"
 * }
 *
 * Response: 200 OK
 * {
 *   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
 *   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 * }
 *
 * // 3. REFRESH TOKEN
 * POST /api/v1/auth/refresh-token
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (refresh token)
 *
 * Response: 200 OK
 * {
 *   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
 *   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 * }
 * </pre>
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Validation ekle (@Valid annotation ile request validation)
 * - Exception handling ekle (@ExceptionHandler ile custom error response)
 * - Rate limiting ekle (brute force koruması)
 * - API documentation ekle (Swagger/OpenAPI annotations)
 * - CORS configuration ekle (frontend için)
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see AuthenticationService Authentication business logic
 * @see RegisterRequest Kayıt request DTO'su
 * @see AuthenticationRequest Login request DTO'su
 * @see AuthenticationResponse Token response DTO'su
 */
@RestController // REST API controller
@RequestMapping("/api/v1/auth") // Base path: /api/v1/auth
@RequiredArgsConstructor // Lombok: final field için constructor
public class AuthenticationController {

  /**
   * Authentication servisi
   *
   * <p>Register, login ve refresh token işlemlerini yöneten servis.</p>
   */
  private final AuthenticationService service;

  /**
   * Yeni kullanıcı kaydı endpoint'i
   *
   * <p><b>NE:</b> Yeni kullanıcı kaydeder ve JWT token'ları döner.</p>
   *
   * <p><b>HTTP METHOD:</b> POST</p>
   * <p><b>PATH:</b> /api/v1/auth/register</p>
   * <p><b>REQUEST BODY:</b> RegisterRequest (JSON)</p>
   * <p><b>RESPONSE:</b> AuthenticationResponse (JSON)</p>
   * <p><b>STATUS CODE:</b> 200 OK</p>
   *
   * <p><b>REQUEST ÖRNEĞİ:</b>
   * <pre>
   * POST /api/v1/auth/register
   * Content-Type: application/json
   * {
   *   "firstname": "Gokhan",
   *   "lastname": "Degerli",
   *   "email": "gokhan@mail.com",
   *   "password": "password123",
   *   "role": "USER"
   * }
   * </pre>
   * </p>
   *
   * <p><b>RESPONSE ÖRNEĞİ:</b>
   * <pre>
   * 200 OK
   * {
   *   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
   *   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * }
   * </pre>
   * </p>
   *
   * <p><b>TODO:</b>
   * - @Valid ekle (request validation)
   * - Exception handling ekle (email duplicate, vb.)
   * - Rate limiting ekle (spam koruması)
   * </p>
   *
   * @param request Kayıt bilgileri (firstname, lastname, email, password, role)
   * @return JWT token'ları içeren response (access token + refresh token)
   * @see RegisterRequest Kayıt request DTO'su
   * @see AuthenticationResponse Token response DTO'su
   * @see AuthenticationService#register(RegisterRequest) Register business logic
   */
  @PostMapping("/register")
  public ResponseEntity<AuthenticationResponse> register(
      @RequestBody
      RegisterRequest request // JSON request body'den RegisterRequest parse edilir
  ) {
    // AuthenticationService.register() çağrılır ve response döner
    return ResponseEntity.ok(service.register(request));
  }

  /**
   * Kullanıcı girişi (login) endpoint'i
   *
   * <p><b>NE:</b> Email ve şifre ile kullanıcı doğrular ve JWT token'ları döner.</p>
   *
   * <p><b>HTTP METHOD:</b> POST</p>
   * <p><b>PATH:</b> /api/v1/auth/authenticate</p>
   * <p><b>REQUEST BODY:</b> AuthenticationRequest (JSON)</p>
   * <p><b>RESPONSE:</b> AuthenticationResponse (JSON)</p>
   * <p><b>STATUS CODE:</b> 200 OK</p>
   *
   * <p><b>REQUEST ÖRNEĞİ:</b>
   * <pre>
   * POST /api/v1/auth/authenticate
   * Content-Type: application/json
   * {
   *   "email": "gokhan@mail.com",
   *   "password": "password123"
   * }
   * </pre>
   * </p>
   *
   * <p><b>RESPONSE ÖRNEĞİ:</b>
   * <pre>
   * 200 OK
   * {
   *   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
   *   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * }
   * </pre>
   * </p>
   *
   * <p><b>EXCEPTION'LAR:</b>
   * - BadCredentialsException: Email veya şifre yanlış (401 Unauthorized)
   * - UsernameNotFoundException: Email DB'de bulunamadı (401 Unauthorized)
   * </p>
   *
   * <p><b>TODO:</b>
   * - @Valid ekle (request validation)
   * - Exception handling ekle (custom error response)
   * - Rate limiting ekle (brute force koruması)
   * - Audit logging ekle (kim ne zaman login oldu)
   * </p>
   *
   * @param request Login bilgileri (email, password)
   * @return JWT token'ları içeren response (access token + refresh token)
   * @see AuthenticationRequest Login request DTO'su
   * @see AuthenticationResponse Token response DTO'su
   * @see AuthenticationService#authenticate(AuthenticationRequest) Login business logic
   */
  @PostMapping("/authenticate")
  public ResponseEntity<AuthenticationResponse> authenticate(
      @RequestBody
      AuthenticationRequest request // JSON request body'den AuthenticationRequest parse edilir
  ) {
    // AuthenticationService.authenticate() çağrılır ve response döner
    return ResponseEntity.ok(service.authenticate(request));
  }

  /**
   * Token yenileme (refresh) endpoint'i
   *
   * <p><b>NE:</b> Refresh token kullanarak yeni access token oluşturur.</p>
   *
   * <p><b>HTTP METHOD:</b> POST</p>
   * <p><b>PATH:</b> /api/v1/auth/refresh-token</p>
   * <p><b>REQUEST HEADER:</b> Authorization: Bearer {refresh_token}</p>
   * <p><b>RESPONSE:</b> AuthenticationResponse (JSON) - response body'ye yazılır</p>
   * <p><b>STATUS CODE:</b> 200 OK</p>
   *
   * <p><b>NEDEN REFRESH TOKEN:</b>
   * - Access token kısa ömürlü (1 gün) -> Güvenlik
   * - Refresh token uzun ömürlü (7 gün) -> Kullanıcı deneyimi
   * - Access token expire olunca refresh token ile yeni token alınır
   * - Kullanıcı sürekli login yapmak zorunda kalmaz
   * </p>
   *
   * <p><b>REQUEST ÖRNEĞİ:</b>
   * <pre>
   * POST /api/v1/auth/refresh-token
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (refresh token)
   * </pre>
   * </p>
   *
   * <p><b>RESPONSE ÖRNEĞİ:</b>
   * <pre>
   * 200 OK
   * {
   *   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
   *   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * }
   * </pre>
   * </p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. Client Authorization header'ında refresh token gönderir
   * 2. AuthenticationService.refreshToken() çağrılır
   * 3. Refresh token validate edilir
   * 4. Yeni access token oluşturulur
   * 5. Response body'ye JSON olarak yazılır (ObjectMapper ile)
   * </p>
   *
   * <p><b>NEDEN VOID DÖNER:</b>
   * Response direkt HttpServletResponse'a yazılır (ObjectMapper ile).
   * ResponseEntity döndürülmez.
   * </p>
   *
   * <p><b>TODO:</b>
   * - Exception handling ekle (token invalid, expired, vb.)
   * - ResponseEntity döndür (void yerine)
   * - Rate limiting ekle (brute force koruması)
   * </p>
   *
   * @param request  HTTP request (Authorization header'ından refresh token alınır)
   * @param response HTTP response (JSON olarak yeni token'lar yazılır)
   * @throws IOException JSON yazma hatası
   * @see AuthenticationService#refreshToken(HttpServletRequest, HttpServletResponse)
   * Refresh token business logic
   */
  @PostMapping("/refresh-token")
  public void refreshToken(HttpServletRequest request,   // HTTP request (Authorization header)
      HttpServletResponse response   // HTTP response (JSON yazılacak)
  ) throws IOException {
    // AuthenticationService.refreshToken() çağrılır
    // Response direkt HttpServletResponse'a yazılır
    service.refreshToken(request, response);
  }
}