package com.degerli.security.auth;

import com.degerli.security.config.JwtService;
import com.degerli.security.token.Token;
import com.degerli.security.token.TokenPurpose;
import com.degerli.security.token.TokenRepository;
import com.degerli.security.token.TokenType;
import com.degerli.security.user.User;
import com.degerli.security.user.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * AuthenticationService - Kullanıcı Kimlik Doğrulama ve Kayıt Servisi
 *
 * <p><b>NE:</b> Kullanıcı kaydı (register), giriş (login) ve token yenileme (refresh)
 * işlemlerini yöneten servis.
 * JWT token oluşturma, kullanıcı doğrulama ve token yönetimi sorumluluklarını üstlenir.</p>
 *
 * <p><b>NEDEN:</b>
 * - Kullanıcı authentication işlemlerini merkezi bir yerden yönetmek
 * - JWT token lifecycle'ını kontrol etmek (create, refresh, revoke)
 * - Güvenli şifre saklama (BCrypt)
 * - Token-based authentication mekanizması
 * - Stateful JWT yönetimi (token'ları DB'de saklamak)
 * </p>
 *
 * <p><b>NASIL ÇALIŞIR:</b>
 *
 * <b>REGISTER AKIŞI:</b>
 * 1. Client RegisterRequest gönderir (firstname, lastname, email, password, role)
 * 2. User entity oluşturulur, şifre BCrypt ile hash'lenir
 * 3. User DB'ye kaydedilir
 * 4. Access token ve refresh token oluşturulur
 * 5. Token'lar DB'ye kaydedilir
 * 6. Token'lar client'a döner
 *
 * <b>LOGIN AKIŞI:</b>
 * 1. Client AuthenticationRequest gönderir (email, password)
 * 2. AuthenticationManager ile kullanıcı doğrulanır
 * 3. Doğrulama başarılıysa user DB'den bulunur
 * 4. Kullanıcının eski token'ları revoke edilir
 * 5. Yeni access token ve refresh token oluşturulur
 * 6. Token'lar DB'ye kaydedilir
 * 7. Token'lar client'a döner
 *
 * <b>REFRESH TOKEN AKIŞI:</b>
 * 1. Client Authorization header'ında refresh token gönderir
 * 2. Refresh token parse edilir ve validate edilir
 * 3. User DB'den bulunur
 * 4. Yeni access token oluşturulur
 * 5. Kullanıcının eski token'ları revoke edilir
 * 6. Yeni token DB'ye kaydedilir
 * 7. Yeni access token ve refresh token client'a döner
 * </p>
 *
 * <p><b>GÜVENLİK ÖZELLİKLERİ:</b>
 * - Şifreler BCrypt ile hash'lenir (plain text saklanmaz)
 * - Token'lar DB'de saklanır (revoke edilebilir)
 * - Eski token'lar otomatik revoke edilir (tek aktif session)
 * - Refresh token ile güvenli token yenileme
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Email duplicate kontrolü ekle (register'da)
 * - Email verification ekle (kayıt sonrası email doğrulama)
 * - Password strength validation ekle
 * - Rate limiting ekle (brute force koruması)
 * - Audit logging ekle (kim ne zaman login oldu)
 * - Multi-device support (birden fazla aktif token)
 * - Exception handling iyileştir (custom exception'lar)
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see JwtService JWT token işlemleri
 * @see UserRepository Kullanıcı DB işlemleri
 * @see TokenRepository Token DB işlemleri
 * @see AuthenticationManager Spring Security authentication
 */
@Service
@RequiredArgsConstructor // Lombok: final field'lar için constructor
public class AuthenticationService {

  /**
   * Kullanıcı veritabanı repository'si
   *
   * <p>Kullanıcı kaydetme, bulma ve güncelleme işlemleri için kullanılır.</p>
   */
  private final UserRepository repository;

  /**
   * Token veritabanı repository'si
   *
   * <p>Token kaydetme, bulma ve revoke işlemleri için kullanılır.</p>
   */
  private final TokenRepository tokenRepository;

  /**
   * Şifre encoder (BCrypt)
   *
   * <p>Şifreleri hash'lemek için kullanılır. ApplicationConfig'de bean olarak tanımlı.</p>
   */
  private final PasswordEncoder passwordEncoder;

  /**
   * JWT servis
   *
   * <p>Token oluşturma, parse etme ve validation işlemleri için kullanılır.</p>
   */
  private final JwtService jwtService;

  /**
   * Spring Security authentication manager
   *
   * <p>Kullanıcı doğrulama (email + password) işlemleri için kullanılır.</p>
   */
  private final AuthenticationManager authenticationManager;

  /**
   * Yeni kullanıcı kaydı yapar
   *
   * <p><b>NE:</b> Yeni kullanıcı oluşturur, şifresini hash'ler, DB'ye kaydeder ve JWT
   * token'ları döner.</p>
   *
   * <p><b>AKIŞ:</b>
   * 1. RegisterRequest'ten User entity oluşturulur
   * 2. Şifre BCrypt ile hash'lenir
   * 3. User DB'ye kaydedilir (repository.save)
   * 4. Access token ve refresh token oluşturulur
   * 5. Token'lar DB'ye kaydedilir
   * 6. AuthenticationResponse döner (access token + refresh token)
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * RegisterRequest request = RegisterRequest.builder()
   *     .firstname("Gokhan")
   *     .lastname("Degerli")
   *     .email("gokhan@mail.com")
   *     .password("password123")
   *     .role(Role.USER)
   *     .build();
   *
   * AuthenticationResponse response = authService.register(request);
   * // response.accessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * // response.refreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * </pre>
   * </p>
   *
   * <p><b>GÜVENLİK:</b>
   * - Şifre plain text olarak asla saklanmaz
   * - BCrypt ile hash'lenir (one-way encryption)
   * - Her kayıt için farklı salt kullanılır (BCrypt otomatik)
   * </p>
   *
   * <p><b>TODO:</b>
   * - Email duplicate kontrolü ekle (aynı email ile iki kayıt olmasın)
   * - Email format validation ekle
   * - Password strength kontrolü ekle (min 8 karakter, büyük harf, rakam, vb.)
   * - Email verification ekle (kayıt sonrası email doğrulama linki)
   * - Exception handling ekle (try-catch ile custom exception)
   * </p>
   *
   * <p><b>KULLANIM YERİ:</b>
   * - AuthenticationController.register(): POST /api/v1/auth/register
   * - SecurityApplication.commandLineRunner(): Uygulama başlangıcında admin/manager oluşturma
   * </p>
   *
   * @param request Kayıt bilgileri (firstname, lastname, email, password, role)
   * @return JWT token'ları içeren response (access token + refresh token)
   * @see RegisterRequest Kayıt request DTO'su
   * @see AuthenticationResponse Token response DTO'su
   * @see #saveUserToken(User, String, TokenPurpose) Token'ı DB'ye kaydeden method
   */
  public AuthenticationResponse register(RegisterRequest request) {
    // 1. RegisterRequest'ten User entity oluştur
    var user = User.builder().firstname(request.getFirstname())      // Ad
        .lastname(request.getLastname())        // Soyad
        .email(request.getEmail())              // Email (username olarak kullanılacak)
        .password(passwordEncoder.encode(request.getPassword())) // Şifreyi BCrypt ile hash'le
        .role(request.getRole())                // Rol (ADMIN, MANAGER, USER)
        .build();

    // 2. User'ı DB'ye kaydet
    var savedUser = repository.save(user);

    // 3. Access token oluştur (1 gün geçerli)
    var jwtToken = jwtService.generateToken(user);

    // 4. Refresh token oluştur (7 gün geçerli)
    var refreshToken = jwtService.generateRefreshToken(user);

    // 3. Her iki token'ı da kaydet
    saveUserToken(savedUser, jwtToken, TokenPurpose.ACCESS); // ❗ ACCESS purpose
    saveUserToken(savedUser, refreshToken, TokenPurpose.REFRESH); // ❗ REFRESH purpose

    // 6. Token'ları döner
    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
        .refreshToken(refreshToken)
        .build();
  }

  /**
   * Kullanıcı girişi yapar (login)
   *
   * <p><b>NE:</b> Email ve şifre ile kullanıcı doğrular, eski token'ları revoke eder ve
   * yeni token'lar döner.</p>
   *
   * <p><b>AKIŞ:</b>
   * 1. AuthenticationManager ile email + password doğrulanır
   * 2. Doğrulama başarılıysa user DB'den bulunur
   * 3. Kullanıcının eski token'ları revoke edilir (tek aktif session)
   * 4. Yeni access token ve refresh token oluşturulur
   * 5. Access token DB'ye kaydedilir
   * 6. Token'lar client'a döner
   * </p>
   *
   * <p><b>AUTHENTICATION MANAGER:</b>
   * - Spring Security'nin authentication mekanizması
   * - UserDetailsService ile user bulunur
   * - PasswordEncoder ile şifre kontrol edilir
   * - Başarılıysa Authentication objesi döner
   * - Başarısızsa BadCredentialsException fırlatır
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * AuthenticationRequest request = AuthenticationRequest.builder()
   *     .email("admin@mail.com")
   *     .password("password")
   *     .build();
   *
   * AuthenticationResponse response = authService.authenticate(request);
   * // response.accessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * // response.refreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * </pre>
   * </p>
   *
   * <p><b>TEK AKTİF SESSION:</b>
   * Login sırasında kullanıcının tüm eski token'ları revoke edilir.
   * Bu sayede aynı anda sadece bir cihazdan login olunabilir.
   *
   * <b>ALTERNATIF:</b> Multi-device support için eski token'ları revoke etme!
   * </p>
   *
   * <p><b>EXCEPTION'LAR:</b>
   * - BadCredentialsException: Email veya şifre yanlış
   * - UsernameNotFoundException: Email DB'de bulunamadı
   * - DisabledException: Hesap devre dışı
   * - LockedException: Hesap kilitli
   * </p>
   *
   * <p><b>TODO:</b>
   * - Rate limiting ekle (5 başarısız denemeden sonra hesap kilitle)
   * - Audit logging ekle (kim ne zaman login oldu)
   * - Multi-device support ekle (eski token'ları revoke etme)
   * - Remember me özelliği ekle (uzun ömürlü token)
   * </p>
   *
   * <p><b>KULLANIM YERİ:</b>
   * - AuthenticationController.authenticate(): POST /api/v1/auth/authenticate
   * </p>
   *
   * @param request Login bilgileri (email, password)
   * @return JWT token'ları içeren response (access token + refresh token)
   * @throws org.springframework.security.authentication.BadCredentialsException Email veya
   *                                                                             şifre yanlış
   * @see AuthenticationRequest Login request DTO'su
   * @see AuthenticationResponse Token response DTO'su
   * @see #revokeAllUserTokens(User) Eski token'ları revoke eden method
   */
  public AuthenticationResponse authenticate(AuthenticationRequest request) {
    // 1. AuthenticationManager ile email + password doğrula
    // Bu satır başarısız olursa BadCredentialsException fırlatır
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(request.getEmail(),    // Username (email)
            request.getPassword()  // Password (plain text)
        ));

    // 2. Doğrulama başarılı, user'ı DB'den bul
    // orElseThrow: User bulunamazsa exception fırlat (normalde bulunamaz çünkü
    // authentication başarılı)
    var user = repository.findByEmail(request.getEmail())
        .orElseThrow(); // UsernameNotFoundException fırlatır

    // 3. Yeni access token oluştur (1 gün geçerli)
    var jwtToken = jwtService.generateToken(user);

    // 4. Yeni refresh token oluştur (7 gün geçerli)
    var refreshToken = jwtService.generateRefreshToken(user);

    // 5. Kullanıcının eski token'larını revoke et (tek aktif session)
    revokeAllUserTokens(user);

    // 5. Yeni token'ları kaydet
    saveUserToken(user, jwtToken, TokenPurpose.ACCESS); // ❗ ACCESS purpose
    saveUserToken(user, refreshToken, TokenPurpose.REFRESH); // ❗ REFRESH purpose

    // 7. Token'ları döner
    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
        .refreshToken(refreshToken)
        .build();
  }

  /**
   * Token'ı DB'ye kaydeder
   *
   * <p><b>NE:</b> Verilen JWT token'ı Token entity olarak DB'ye kaydeder.</p>
   *
   * <p><b>NEDEN:</b>
   * - Stateful JWT için token'ları DB'de saklamak
   * - Token'ı revoke edebilmek (logout)
   * - Token validation sırasında DB'den kontrol etmek
   * - Kullanıcının tüm aktif token'larını görebilmek
   * </p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. Token entity oluşturulur
   * 2. Token string, user, tokenType set edilir
   * 3. expired ve revoked false olarak set edilir (yeni token geçerli)
   * 4. Token DB'ye kaydedilir
   * </p>
   *
   * <p><b>TOKEN DURUMU:</b>
   * - expired: false (yeni oluşturuldu, henüz expire olmadı)
   * - revoked: false (henüz iptal edilmedi)
   * - tokenType: BEARER (HTTP Authorization header'ında kullanılacak)
   * </p>
   *
   * <p><b>KULLANIM YERLERİ:</b>
   * - register(): Kayıt sonrası token kaydetme
   * - authenticate(): Login sonrası token kaydetme
   * - refreshToken(): Refresh sonrası yeni token kaydetme
   * </p>
   *
   * @param user         Token'ın sahibi olan kullanıcı
   * @param jwtToken     JWT token string'i
   * @param tokenPurpose Token amacı (ACCESS veya REFRESH)
   * @see Token Token entity'si
   * @see TokenType Token tipi enum'u
   */
  private void saveUserToken(User user, String jwtToken, TokenPurpose tokenPurpose) {
    // 1. Token entity oluştur
    var token = Token.builder()
        .user(user)                      // Token'ın sahibi
        .token(jwtToken)                 // JWT token string'i
        .tokenType(TokenType.BEARER)    // Token tipi: BEARER
        .tokenPurpose(tokenPurpose)
        .expired(false)                  // Yeni token, expire olmamış
        .revoked(false)                  // Yeni token, revoke edilmemiş
        .build();

    // 2. Token'ı DB'ye kaydet
    tokenRepository.save(token);
  }

  /**
   * Kullanıcının tüm geçerli token'larını revoke eder
   *
   * <p><b>NE:</b> Kullanıcıya ait tüm aktif token'ları expired ve revoked olarak işaretler
   * .</p>
   *
   * <p><b>NEDEN:</b>
   * - Logout işleminde tüm token'ları geçersiz kılmak
   * - Login sırasında eski token'ları iptal etmek (tek aktif session)
   * - Refresh token sırasında eski token'ları iptal etmek
   * - Güvenlik: Çalınan token'ı manuel olarak iptal edebilmek
   * </p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. TokenRepository'den kullanıcının tüm geçerli token'ları bulunur
   * 2. Liste boş değilse her token için:
   * - expired = true
   * - revoked = true
   * 3. Tüm token'lar DB'ye kaydedilir (bulk update)
   * </p>
   *
   * <p><b>PERFORMANS:</b>
   * - findAllValidTokenByUser(): Tek query ile tüm token'lar bulunur
   * - saveAll(): Bulk update ile tüm token'lar güncellenir (tek query)
   * - Alternatif: Custom update query ile daha hızlı yapılabilir
   * </p>
   *
   * <p><b>KULLANIM YERLERİ:</b>
   * - authenticate(): Login sırasında eski token'ları iptal etme
   * - refreshToken(): Refresh sırasında eski token'ları iptal etme
   * - LogoutService.logout(): Logout sırasında token'ı iptal etme
   * </p>
   *
   * <p><b>TODO:</b>
   * - Custom update query ile performans iyileştirmesi:
   * <pre>
   *   {@literal @}Query("UPDATE Token t SET t.expired = true, t.revoked = true WHERE t.user.id = :userId")
   *   void revokeAllUserTokens(@Param("userId") Integer userId);
   *   </pre>
   * </p>
   *
   * @param user Token'ları revoke edilecek kullanıcı
   * @see TokenRepository#findAllValidTokenByUser(Integer) Geçerli token'ları bulan method
   */
  private void revokeAllUserTokens(User user) {
    // 1. Kullanıcının tüm geçerli token'larını bul
    var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());

    // 2. Token listesi boşsa işlem yapma (early return)
    if (validUserTokens.isEmpty()) {
      return;
    }

    // 3. Her token'ı expired ve revoked olarak işaretle
    validUserTokens.forEach(token -> {
      token.setExpired(true);  // Token süresi doldu olarak işaretle
      token.setRevoked(true);  // Token iptal edildi olarak işaretle
    });

    // 4. Tüm token'ları DB'ye kaydet (bulk update)
    tokenRepository.saveAll(validUserTokens);
  }

  /**
   * Kullanıcının belirli amaçtaki tüm geçerli token'larını revoke eder
   */

  private void revokeAllUserTokensByPurpose(User user, TokenPurpose tokenPurpose) {
    var validUserTokens = tokenRepository.findAllValidTokenByUserAndPurpose(user.getId(),
        tokenPurpose);
    if (validUserTokens.isEmpty()) {
      return;
    }
    validUserTokens.forEach(token -> {
      token.setExpired(true);
      token.setRevoked(true);
    });
    tokenRepository.saveAll(validUserTokens);
  }

  /**
   * Refresh token ile yeni access token oluşturur
   *
   * <p><b>NE:</b> Refresh token kullanarak yeni access token ve refresh token oluşturur.
   * Access token expire olduğunda kullanıcı tekrar login yapmadan yeni token alabilir.</p>
   *
   * <p><b>REFRESH TOKEN AKIŞI:</b>
   * 1. Client Authorization header'ında refresh token gönderir
   * 2. Refresh token parse edilir ve username (email) çıkarılır
   * 3. User DB'den bulunur
   * 4. Refresh token validate edilir (expire olmamış mı, user'a ait mi)
   * 5. Yeni access token oluşturulur
   * 6. Kullanıcının eski token'ları revoke edilir
   * 7. Yeni access token DB'ye kaydedilir
   * 8. Yeni access token ve refresh token response'a yazılır (JSON)
   * </p>
   *
   * <p><b>NEDEN REFRESH TOKEN:</b>
   * - Access token kısa ömürlü (1 gün) -> Güvenlik
   * - Refresh token uzun ömürlü (7 gün) -> Kullanıcı deneyimi
   * - Access token expire olunca refresh token ile yeni token alınır
   * - Kullanıcı sürekli login yapmak zorunda kalmaz
   * </p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. Request'ten Authorization header alınır
   * 2. "Bearer " prefix'i kaldırılır, refresh token çıkarılır
   * 3. Refresh token'dan username (email) parse edilir
   * 4. User DB'den bulunur
   * 5. Refresh token validate edilir (jwtService.isTokenValid)
   * 6. Yeni access token oluşturulur
   * 7. Eski token'lar revoke edilir
   * 8. Yeni token DB'ye kaydedilir
   * 9. Response'a JSON olarak yazılır
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
   * {
   *   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
   *   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * }
   * </pre>
   * </p>
   *
   * <p><b>GÜVENLİK:</b>
   * - Refresh token validate edilir (expire kontrolü, user kontrolü)
   * - Eski token'lar revoke edilir (token rotation)
   * - Her refresh'te yeni refresh token da oluşturulur (güvenlik)
   * </p>
   *
   * <p><b>TODO:</b>
   * - Exception handling ekle (token invalid, expired, vb.)
   * - Refresh token rotation stratejisi ekle
   * - Refresh token blacklist ekle (Redis)
   * - Rate limiting ekle (brute force koruması)
   * </p>
   *
   * <p><b>KULLANIM YERİ:</b>
   * - AuthenticationController.refreshToken(): POST /api/v1/auth/refresh-token
   * </p>
   *
   * @param request  HTTP request (Authorization header'ından refresh token alınır)
   * @param response HTTP response (JSON olarak yeni token'lar yazılır)
   * @throws IOException JSON yazma hatası
   * @see JwtService#extractUsername(String) Token'dan username çıkarır
   * @see JwtService#isTokenValid(String, UserDetails) Token validation
   * @see JwtService#generateToken(UserDetails) Yeni access token oluşturur
   */
  public void refreshToken(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    // 1. Request'ten Authorization header'ı al
    final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    final String refreshToken;
    final String userEmail;

    // 2. Authorization header yoksa veya "Bearer " ile başlamıyorsa işlem yapma
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return; // Early return (hata fırlatmıyor, sessizce çıkıyor)
    }

    // 3. "Bearer " prefix'ini kaldır, refresh token'ı al
    refreshToken = authHeader.substring(7); // "Bearer " 7 karakter

    // 4. Refresh token'dan username (email) çıkar
    userEmail = jwtService.extractUsername(refreshToken);

    // 5. Email varsa user'ı DB'den bul
    if (userEmail != null) {
      // 6. User'ı DB'den bul
      var user = this.repository.findByEmail(userEmail)
          .orElseThrow(); // User bulunamazsa exception fırlat

      // 7. Refresh token validate et (expire olmamış mı, user'a ait mi)
      if (jwtService.isTokenValid(refreshToken, user)) {

        // 5. Refresh token database'de var mı ve REFRESH purpose'u mu kontrol et
        var storedToken = tokenRepository.findByTokenAndTokenPurpose(refreshToken,
            TokenPurpose.REFRESH // ❗ REFRESH purpose kontrolü
        );

        if (storedToken.isEmpty() || storedToken.get().isRevoked() || storedToken.get()
            .isExpired()) {
          // ❗ Refresh token geçersiz
          response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
          return;
        }

        // 8. Yeni access token oluştur
        var accessToken = jwtService.generateToken(user);

        // 9. Sadece eski ACCESS token'ları revoke et
        revokeAllUserTokensByPurpose(user, TokenPurpose.ACCESS); // ❗ ACCESS purpose

        // 10. Yeni access token'ı kaydet
        saveUserToken(user, accessToken, TokenPurpose.ACCESS); // ❗ ACCESS purpose

        // 11. Response oluştur (access token + refresh token)
        var authResponse = AuthenticationResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken) // Aynı refresh token döner (veya yeni oluşturulabilir)
            .build();

        // 12. Response'a JSON olarak yaz
        new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
      }
    }
  }
}