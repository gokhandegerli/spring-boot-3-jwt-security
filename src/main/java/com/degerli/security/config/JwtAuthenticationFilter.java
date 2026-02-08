package com.degerli.security.config;

import com.degerli.security.token.TokenPurpose;
import com.degerli.security.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * JwtAuthenticationFilter - JWT Token Validation Filter
 *
 * <p><b>NE:</b> Her HTTP request'te JWT token'ı validate eden Spring Security filter'ı.
 * Authorization header'dan JWT token'ı alır, validate eder ve SecurityContext'e
 * Authentication set eder.</p>
 *
 * <p><b>NEDEN:</b>
 * - JWT token-based authentication sağlamak
 * - Her request'te token'ı otomatik olarak validate etmek
 * - Valid token varsa kullanıcıyı authenticate etmek
 * - Invalid/expired token varsa request'i reddetmek
 * - Stateless authentication sağlamak (session kullanmadan)
 * </p>
 *
 * <p><b>NASIL:</b>
 *
 * <b>1. OncePerRequestFilter:</b>
 * - Spring'in sağladığı abstract filter class
 * - Her request için sadece bir kez çalışır (duplicate execution'ı önler)
 * - doFilterInternal() method'unu override ederiz
 *
 * <b>2. FILTER EXECUTION ORDER:</b>
 * SecurityConfiguration'da tanımlanır:
 * <pre>
 * .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
 * </pre>
 * <p>
 * Filter chain sırası:
 * 1. JwtAuthenticationFilter (JWT token validate)
 * 2. UsernamePasswordAuthenticationFilter (username/password authentication)
 * 3. ExceptionTranslationFilter (exception handling)
 * 4. FilterSecurityInterceptor (authorization)
 *
 * <b>3. AUTHENTICATION FLOW:</b>
 * 1. Request gelir (Authorization header ile)
 * 2. JwtAuthenticationFilter.doFilterInternal() çağrılır
 * 3. Authorization header'dan JWT token alınır
 * 4. Token validate edilir (JwtService.isTokenValid())
 * 5. Token valid ise:
 * - UserDetailsService.loadUserByUsername() ile user yüklenir
 * - UsernamePasswordAuthenticationToken oluşturulur
 * - SecurityContext'e Authentication set edilir
 * 6. Token invalid ise:
 * - SecurityContext boş kalır
 * - FilterSecurityInterceptor 403 Forbidden döner
 * 7. Filter chain devam eder (filterChain.doFilter())
 *
 * <b>4. TOKEN VALIDATION:</b>
 * - Token expired mi? (JwtService.isTokenValid())
 * - Token revoked mi? (TokenRepository.findByToken())
 * - Token signature valid mi? (JwtService.isTokenValid())
 * - Token user'ı mevcut mu? (UserDetailsService.loadUserByUsername())
 * </p>
 *
 * <p><b>AUTHORIZATION HEADER FORMAT:</b>
 * <pre>
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbkBtYWlsLmNvbSIsImlhdCI6MTYxNjIzOTAyMiwiZXhwIjoxNjE2MzI1NDIyfQ.4X8sP7_Kq5Z9X8Y7Z8X8Y7Z8X8Y7Z8X8Y7Z8X8Y7Z8
 *
 * Format: "Bearer <JWT_TOKEN>"
 * - "Bearer " prefix (7 karakter, space dahil)
 * - JWT token (3 part: header.payload.signature)
 * </pre>
 * </p>
 *
 * <p><b>SECURITY CONTEXT:</b>
 *
 * <b>SecurityContextHolder:</b>
 * - Spring Security'nin thread-local storage'ı
 * - Her thread için ayrı SecurityContext tutar
 * - Current user bilgisini saklar
 *
 * <b>SecurityContext:</b>
 * - Authentication object'i tutar
 * - SecurityContextHolder.getContext().getAuthentication() ile alınır
 *
 * <b>Authentication:</b>
 * - Principal: User object (UserDetails implementation)
 * - Credentials: Password (genellikle null)
 * - Authorities: User'ın rolleri ve permission'ları
 * </p>
 *
 * <p><b>KULLANIM ÖRNEĞİ:</b>
 * <pre>
 * // 1. LOGIN YAP VE TOKEN AL
 * POST /api/v1/auth/authenticate
 * {
 *   "email": "admin@mail.com",
 *   "password": "password"
 * }
 * Response: { "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }
 *
 * // 2. TOKEN İLE REQUEST AT
 * GET /api/v1/books
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *
 * // 3. JwtAuthenticationFilter ÇALIŞIR:
 * // - Authorization header'dan token alınır
 * // - Token validate edilir
 * // - User yüklenir (admin@mail.com)
 * // - SecurityContext'e Authentication set edilir
 * // - Filter chain devam eder
 * // - Controller method çağrılır
 * // - Response döner: 200 OK
 *
 * // 4. INVALID TOKEN İLE REQUEST AT
 * GET /api/v1/books
 * Authorization: Bearer invalid_token
 *
 * // 5. JwtAuthenticationFilter ÇALIŞIR:
 * // - Authorization header'dan token alınır
 * // - Token validate edilir (FAILED)
 * // - SecurityContext boş kalır
 * // - Filter chain devam eder
 * // - FilterSecurityInterceptor 403 Forbidden döner
 * </pre>
 * </p>
 *
 * <p><b>WHITELISTED ENDPOINTS:</b>
 * SecurityConfiguration'da tanımlanan whitelisted endpoint'ler için
 * JWT token gerektirmez:
 * <pre>
 * .requestMatchers("/api/v1/auth/**").permitAll()
 * </pre>
 * <p>
 * Bu endpoint'ler için:
 * - JwtAuthenticationFilter çalışır ama token yoksa skip eder
 * - SecurityContext boş kalır
 * - Controller method çağrılır (authentication gerektirmez)
 * </p>
 *
 * <p><b>TOKEN REVOCATION:</b>
 * Logout yapıldığında token revoke edilir:
 * <pre>
 * POST /api/v1/auth/logout
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * </pre>
 * <p>
 * LogoutService:
 * - Token'ı DB'de bulur
 * - expired = true, revoked = true set eder
 * - SecurityContext temizler
 * <p>
 * Revoked token ile request atılırsa:
 * - JwtAuthenticationFilter token'ı validate eder
 * - TokenRepository.findByToken() ile token bulunur
 * - token.expired == true veya token.revoked == true
 * - Token invalid sayılır
 * - SecurityContext boş kalır
 * - 403 Forbidden döner
 * </p>
 *
 * <p><b>EXCEPTION HANDLING:</b>
 *
 * <b>1. Token parse exception:</b>
 * - JwtService.extractUsername() exception fırlatır
 * - Filter exception'ı catch etmez (Spring Security handle eder)
 * - 403 Forbidden döner
 *
 * <b>2. User not found:</b>
 * - UserDetailsService.loadUserByUsername() UsernameNotFoundException fırlatır
 * - Filter exception'ı catch etmez
 * - 403 Forbidden döner
 *
 * <b>3. Token expired:</b>
 * - JwtService.isTokenValid() false döner
 * - SecurityContext boş kalır
 * - 403 Forbidden döner
 * </p>
 *
 * <p><b>PERFORMANCE CONSIDERATIONS:</b>
 *
 * <b>1. DB Query:</b>
 * Her request'te 2 DB query yapılır:
 * - UserDetailsService.loadUserByUsername() (user query)
 * - TokenRepository.findByToken() (token query)
 *
 * <b>TODO:</b>
 * - Redis cache ekle (user ve token için)
 * - Token validation'ı cache'le (aynı token için tekrar DB'ye gitme)
 *
 * <b>2. Token Parsing:</b>
 * Her request'te JWT token parse edilir (CPU intensive)
 *
 * <b>TODO:</b>
 * - Token parsing sonucunu cache'le
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Exception handling ekle (custom exception messages)
 * - Logging ekle (failed authentication attempts)
 * - Rate limiting ekle (brute force attack'lere karşı)
 * - Redis cache ekle (performance için)
 * - Token blacklist ekle (revoked token'ları cache'le)
 * - Custom AuthenticationEntryPoint ekle (401/403 response customize)
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see OncePerRequestFilter Spring filter base class
 * @see JwtService JWT token service
 * @see UserDetailsService User details service
 * @see TokenRepository Token repository
 * @see SecurityConfiguration Security config
 */
@Component // Spring component (bean olarak register edilir)
@RequiredArgsConstructor // Lombok: final field için constructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  /**
   * JWT service
   *
   * <p>JWT token işlemleri için kullanılır (extract, validate, vb.).</p>
   */
  private final JwtService jwtService;

  /**
   * User details service
   *
   * <p>Kullanıcı bilgilerini yüklemek için kullanılır.</p>
   */
  private final UserDetailsService userDetailsService;

  /**
   * Token repository
   *
   * <p>Token'ın revoked/expired olup olmadığını kontrol etmek için kullanılır.</p>
   */
  private final TokenRepository tokenRepository;

  /**
   * Filter method - Her request'te çalışır
   *
   * <p><b>NE:</b> Her HTTP request'te JWT token'ı validate eder ve
   * SecurityContext'e Authentication set eder.</p>
   *
   * <p><b>EXECUTION FLOW:</b>
   *
   * <b>1. Authorization Header Kontrolü:</b>
   * - Authorization header var mı?
   * - "Bearer " prefix ile mi başlıyor?
   * - Yoksa filter chain'e devam et (authentication yapma)
   *
   * <b>2. JWT Token Extraction:</b>
   * - Authorization header'dan "Bearer " prefix'i kaldır
   * - JWT token'ı al (substring(7))
   * - JwtService.extractUsername() ile username (email) çıkar
   *
   * <b>3. User Authentication Kontrolü:</b>
   * - SecurityContext'te Authentication var mı?
   * - Yoksa user'ı authenticate et
   * - Varsa skip et (zaten authenticated)
   *
   * <b>4. User Loading:</b>
   * - UserDetailsService.loadUserByUsername() ile user yükle
   * - User bulunamazsa UsernameNotFoundException fırlatılır
   *
   * <b>5. Token Validation:</b>
   * - JwtService.isTokenValid() ile token validate et
   * - Token expired mi?
   * - Token signature valid mi?
   * - Token revoked mi? (TokenRepository.findByToken())
   *
   * <b>6. Authentication Object Oluşturma:</b>
   * - UsernamePasswordAuthenticationToken oluştur
   * - Principal: UserDetails (user)
   * - Credentials: null (password gerekli değil)
   * - Authorities: User'ın rolleri ve permission'ları
   *
   * <b>7. Authentication Details Set Etme:</b>
   * - WebAuthenticationDetailsSource ile details oluştur
   * - Request IP, session ID gibi bilgiler
   * - authToken.setDetails()
   *
   * <b>8. SecurityContext'e Set Etme:</b>
   * - SecurityContextHolder.getContext().setAuthentication()
   * - Artık user authenticated
   * - Controller'da @AuthenticationPrincipal ile alınabilir
   *
   * <b>9. Filter Chain Devam:</b>
   * - filterChain.doFilter() çağrılır
   * - Sonraki filter'a geçilir
   * - En sonunda controller method çağrılır
   * </p>
   *
   * <p><b>AUTHORIZATION HEADER PARSING:</b>
   * <pre>
   * // Authorization header:
   * "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   *
   * // authHeader != null: true
   * // authHeader.startsWith("Bearer "): true
   *
   * // JWT token extraction:
   * jwt = authHeader.substring(7)
   * // jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   *
   * // Username extraction:
   * userEmail = jwtService.extractUsername(jwt)
   * // userEmail = "admin@mail.com"
   * </pre>
   * </p>
   *
   * <p><b>SECURITY CONTEXT CHECK:</b>
   * <pre>
   * // SecurityContext'te Authentication var mı?
   * SecurityContextHolder.getContext().getAuthentication() == null
   *
   * // Neden kontrol ediyoruz?
   * // - User zaten authenticated olabilir (önceki filter'da)
   * // - Duplicate authentication'ı önlemek için
   * // - Performance için (gereksiz DB query'den kaçınmak)
   * </pre>
   * </p>
   *
   * <p><b>TOKEN VALIDATION DETAYLARI:</b>
   * <pre>
   * // JwtService.isTokenValid() kontrolü:
   * boolean isTokenValid = tokenRepository.findByToken(jwt)
   *     .map(t -> !t.isExpired() && !t.isRevoked()) // Token revoked/expired değil mi?
   *     .orElse(false); // Token DB'de yok mu?
   *
   * // Token valid ise:
   * if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
   *     // Authentication object oluştur ve SecurityContext'e set et
   * }
   * </pre>
   * </p>
   *
   * <p><b>AUTHENTICATION TOKEN OLUŞTURMA:</b>
   * <pre>
   * // UsernamePasswordAuthenticationToken:
   * UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
   *     userDetails,           // Principal (User object)
   *     null,                  // Credentials (password gerekli değil)
   *     userDetails.getAuthorities() // Authorities (roles + permissions)
   * );
   *
   * // Authentication details set et:
   * authToken.setDetails(
   *     new WebAuthenticationDetailsSource().buildDetails(request)
   * );
   * // Details: request IP, session ID, vb.
   *
   * // SecurityContext'e set et:
   * SecurityContextHolder.getContext().setAuthentication(authToken);
   * </pre>
   * </p>
   *
   * <p><b>WHITELISTED ENDPOINT HANDLING:</b>
   * <pre>
   * // Whitelisted endpoint (örn: /api/v1/auth/register):
   * // - Authorization header yok
   * // - authHeader == null
   * // - Filter skip edilir (filterChain.doFilter())
   * // - SecurityContext boş kalır
   * // - Controller method çağrılır (authentication gerektirmez)
   * </pre>
   * </p>
   *
   * <p><b>INVALID TOKEN HANDLING:</b>
   * <pre>
   * // Invalid token:
   * // - JwtService.isTokenValid() false döner
   * // - SecurityContext boş kalır
   * // - Filter chain devam eder
   * // - FilterSecurityInterceptor 403 Forbidden döner
   * </pre>
   * </p>
   *
   * <p><b>@NonNull ANNOTATION:</b>
   * - Spring'in null-safety annotation'ı
   * - Parameter null olamaz
   * - IDE warning verir (null geçilirse)
   * </p>
   *
   * <p><b>TODO:</b>
   * - Exception handling ekle (try-catch)
   * - Logging ekle (failed authentication attempts)
   * - Rate limiting ekle (brute force attack'lere karşı)
   * - Redis cache ekle (user ve token için)
   * - Custom error response döndür (401/403)
   * </p>
   *
   * @param request     HTTP request
   * @param response    HTTP response
   * @param filterChain Filter chain (sonraki filter'a geçmek için)
   * @throws ServletException Servlet exception
   * @throws IOException      IO exception
   */
  @Override
  protected void doFilterInternal(
      @NonNull
      HttpServletRequest request,
      @NonNull
      HttpServletResponse response,
      @NonNull
      FilterChain filterChain) throws ServletException, IOException {
    // 1. Authorization header'ı al
    final String authHeader = request.getHeader("Authorization");
    final String jwt;
    final String userEmail;

    // 2. Authorization header kontrolü
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      // Authorization header yok veya "Bearer " ile başlamıyor
      // Filter chain'e devam et (authentication yapma)
      filterChain.doFilter(request, response);
      return;
    }

    // 3. JWT token'ı extract et
    jwt = authHeader.substring(7); // "Bearer " prefix'ini kaldır (7 karakter)
    userEmail = jwtService.extractUsername(jwt); // JWT'den username (email) çıkar

    // 4. User email var mı ve SecurityContext'te Authentication yok mu?
    if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      // 5. User'ı DB'den yükle
      UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

      // 6. Token database'de var mı ve ACCESS purpose'u mu kontrol et
      var isTokenValid = tokenRepository.findByTokenAndTokenPurpose(jwt, TokenPurpose.ACCESS
          // ❗ ACCESS purpose kontrolü
      ).map(t -> !t.isExpired() && !t.isRevoked()).orElse(false);

      // 7. Token valid mi? (signature, expiration, revocation kontrolü)
      if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
        // 8. Authentication object oluştur
        UsernamePasswordAuthenticationToken authToken
            = new UsernamePasswordAuthenticationToken(userDetails,
            // Principal (User object)
            null,                           // Credentials (password gerekli değil)
            userDetails.getAuthorities()    // Authorities (roles + permissions)
        );

        // 9. Authentication details set et (request IP, session ID, vb.)
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        // 10. SecurityContext'e Authentication set et
        SecurityContextHolder.getContext().setAuthentication(authToken);
      }
    }

    // 11. Filter chain'e devam et (sonraki filter'a geç)
    filterChain.doFilter(request, response);
  }
}