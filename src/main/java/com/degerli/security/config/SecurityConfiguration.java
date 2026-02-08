package com.degerli.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import static com.degerli.security.user.Permission.ADMIN_CREATE;
import static com.degerli.security.user.Permission.ADMIN_DELETE;
import static com.degerli.security.user.Permission.ADMIN_READ;
import static com.degerli.security.user.Permission.ADMIN_UPDATE;
import static com.degerli.security.user.Permission.MANAGER_CREATE;
import static com.degerli.security.user.Permission.MANAGER_DELETE;
import static com.degerli.security.user.Permission.MANAGER_READ;
import static com.degerli.security.user.Permission.MANAGER_UPDATE;
import static com.degerli.security.user.Role.ADMIN;
import static com.degerli.security.user.Role.MANAGER;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

/**
 * SecurityConfiguration - Spring Security Configuration
 *
 * <p><b>NE:</b> Spring Security'nin core configuration'ı.
 * Authentication, authorization, JWT filter, logout handling gibi
 * tüm security ayarlarını içerir.</p>
 *
 * <p><b>NEDEN:</b>
 * - Hangi endpoint'lerin korunacağını belirlemek
 * - JWT authentication filter'ı eklemek
 * - Role-based ve permission-based access control sağlamak
 * - Logout handling yapmak
 * - CSRF, CORS, session management gibi security ayarlarını yapmak
 * </p>
 *
 * <p><b>NASIL:</b>
 *
 * <b>1. WHITELISTED ENDPOINTS:</b>
 * Aşağıdaki endpoint'ler authentication gerektirmez:
 * - /api/v1/auth/** (register, login, refresh-token)
 * - /v2/api-docs, /v3/api-docs/** (Swagger API docs)
 * - /swagger-resources/** (Swagger resources)
 * - /swagger-ui/** (Swagger UI)
 * - /webjars/** (Swagger webjars)
 *
 * <b>2. MANAGEMENT ENDPOINTS:</b>
 * /api/v1/management/** endpoint'leri için role ve permission-based access control:
 * - ADMIN ve MANAGER rolleri erişebilir
 * - GET: admin:read veya manager:read permission gerekli
 * - POST: admin:create veya manager:create permission gerekli
 * - PUT: admin:update veya manager:update permission gerekli
 * - DELETE: admin:delete veya manager:delete permission gerekli
 *
 * <b>3. ADMIN ENDPOINTS:</b>
 * /api/v1/admin/** endpoint'leri için @PreAuthorize annotation kullanılır.
 * SecurityConfiguration'da tanımlanmaz, AdminController'da method-level security vardır.
 *
 * <b>4. OTHER ENDPOINTS:</b>
 * Diğer tüm endpoint'ler authenticated user'lar tarafından erişilebilir.
 *
 * <b>5. JWT FILTER:</b>
 * JwtAuthenticationFilter, her request'te JWT token'ı validate eder.
 * UsernamePasswordAuthenticationFilter'dan önce çalışır.
 *
 * <b>6. LOGOUT HANDLING:</b>
 * /api/v1/auth/logout endpoint'i için custom logout handler kullanılır.
 * LogoutService, token'ı revoke eder ve SecurityContext'i temizler.
 *
 * <b>7. SESSION MANAGEMENT:</b>
 * STATELESS session policy kullanılır (JWT için gerekli).
 * Server-side session oluşturulmaz.
 *
 * <b>8. CSRF:</b>
 * CSRF koruması devre dışı bırakılır (JWT kullanıldığı için gerekli değil).
 * </p>
 *
 * <p><b>SECURITY FILTER CHAIN:</b>
 * 1. JwtAuthenticationFilter (JWT token validate)
 * 2. UsernamePasswordAuthenticationFilter (username/password authentication)
 * 3. ExceptionTranslationFilter (exception handling)
 * 4. FilterSecurityInterceptor (authorization)
 * </p>
 *
 * <p><b>AUTHORIZATION FLOW:</b>
 * 1. Request gelir
 * 2. JwtAuthenticationFilter JWT token'ı validate eder
 * 3. SecurityContext'e Authentication object set edilir
 * 4. FilterSecurityInterceptor authorization kontrolü yapar
 * 5. Authorized ise controller method çağrılır
 * 6. Unauthorized ise 403 Forbidden döner
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - CORS configuration ekle (frontend için)
 * - Rate limiting ekle (brute force attack'lere karşı)
 * - Custom AccessDeniedHandler ekle (403 response customize)
 * - Custom AuthenticationEntryPoint ekle (401 response customize)
 * - Security headers ekle (X-Frame-Options, X-Content-Type-Options, vb.)
 * - HTTPS enforcement ekle (production için)
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see JwtAuthenticationFilter JWT filter
 * @see LogoutService Logout handler
 * @see ApplicationConfig Authentication provider
 */
@Configuration // Spring configuration class
@EnableWebSecurity // Spring Security'yi enable et
@RequiredArgsConstructor // Lombok: final field için constructor
@EnableMethodSecurity // Method-level security enable et (@PreAuthorize, @Secured, vb.)
public class SecurityConfiguration {

  /**
   * JWT authentication filter
   *
   * <p>Her request'te JWT token'ı validate eder.</p>
   */
  private final JwtAuthenticationFilter jwtAuthFilter;

  /**
   * Authentication provider
   *
   * <p>Username/password authentication için kullanılır.</p>
   */
  private final AuthenticationProvider authenticationProvider;

  /**
   * Logout handler
   *
   * <p>Logout sırasında token'ı revoke eder.</p>
   */
  private final LogoutHandler logoutHandler;

  /**
   * Security Filter Chain Bean
   *
   * <p><b>NE:</b> Spring Security'nin core configuration'ı.
   * Hangi endpoint'lerin korunacağını, hangi filter'ların kullanılacağını,
   * logout handling'i, session management'ı belirler.</p>
   *
   * <p><b>CONFIGURATION DETAYLARI:</b>
   *
   * <b>1. CSRF (Cross-Site Request Forgery):</b>
   * - Devre dışı bırakılır (JWT kullanıldığı için gerekli değil)
   * - JWT token, CSRF token'a ihtiyaç duymaz
   * - Stateless authentication için CSRF koruması gerekmez
   *
   * <b>2. AUTHORIZATION RULES:</b>
   *
   * <b>2.1. Whitelisted Endpoints (Authentication gerektirmez):</b>
   * - /api/v1/auth/** (register, login, refresh-token)
   * - /v2/api-docs, /v3/api-docs/** (Swagger API docs)
   * - /swagger-resources/** (Swagger resources)
   * - /swagger-ui/** (Swagger UI)
   * - /webjars/** (Swagger webjars)
   *
   * <b>2.2. Management Endpoints (Role + Permission based):</b>
   * - /api/v1/management/** -> ADMIN veya MANAGER rolü gerekli
   * - GET /api/v1/management/** -> admin:read veya manager:read permission
   * - POST /api/v1/management/** -> admin:create veya manager:create permission
   * - PUT /api/v1/management/** -> admin:update veya manager:update permission
   * - DELETE /api/v1/management/** -> admin:delete veya manager:delete permission
   *
   * <b>2.3. Other Endpoints:</b>
   * - Diğer tüm endpoint'ler authenticated user'lar tarafından erişilebilir
   *
   * <b>3. SESSION MANAGEMENT:</b>
   * - STATELESS policy kullanılır
   * - Server-side session oluşturulmaz
   * - JWT token her request'te gönderilir
   *
   * <b>4. AUTHENTICATION PROVIDER:</b>
   * - ApplicationConfig'de tanımlanan provider kullanılır
   * - DaoAuthenticationProvider (DB'den kullanıcı bilgilerini alır)
   *
   * <b>5. JWT FILTER:</b>
   * - JwtAuthenticationFilter, UsernamePasswordAuthenticationFilter'dan önce çalışır
   * - Her request'te JWT token validate edilir
   * - Valid token varsa SecurityContext'e Authentication set edilir
   *
   * <b>6. LOGOUT HANDLING:</b>
   * - /api/v1/auth/logout endpoint'i için custom logout handler
   * - LogoutService, token'ı revoke eder
   * - SecurityContext temizlenir
   * - Logout success handler SecurityContextHolder.clearContext() çağırır
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * // 1. WHITELISTED ENDPOINT (Authentication gerektirmez)
   * POST /api/v1/auth/register
   * Response: 200 OK
   *
   * // 2. AUTHENTICATED ENDPOINT (JWT token gerekli)
   * GET /api/v1/books
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   * Response: 200 OK
   *
   * // 3. ROLE-BASED ENDPOINT (MANAGER veya ADMIN rolü gerekli)
   * GET /api/v1/management
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (MANAGER token)
   * Response: 200 OK
   *
   * // 4. PERMISSION-BASED ENDPOINT (admin:read permission gerekli)
   * GET /api/v1/management
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (ADMIN token)
   * Response: 200 OK
   *
   * // 5. LOGOUT
   * POST /api/v1/auth/logout
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   * Response: 200 OK
   * </pre>
   * </p>
   *
   * <p><b>TODO:</b>
   * - CORS configuration ekle
   * - Custom AccessDeniedHandler ekle
   * - Custom AuthenticationEntryPoint ekle
   * - Security headers ekle
   * - HTTPS enforcement ekle
   * </p>
   *
   * @param http HttpSecurity builder
   * @return SecurityFilterChain instance
   * @throws Exception Configuration hatası olursa
   */
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        // CSRF korumasını devre dışı bırak (JWT kullanıldığı için gerekli değil)
        .csrf(AbstractHttpConfigurer::disable)

        // Authorization rules
        .authorizeHttpRequests(req -> req
            // Whitelisted endpoints (authentication gerektirmez)
            .requestMatchers("/api/v1/auth/**", // Register, login, refresh-token
                "/v2/api-docs", // Swagger API docs v2
                "/v3/api-docs", // Swagger API docs v3
                "/v3/api-docs/**", // Swagger API docs v3 (all)
                "/swagger-resources", // Swagger resources
                "/swagger-resources/**", // Swagger resources (all)
                "/configuration/ui", // Swagger UI configuration
                "/configuration/security", // Swagger security configuration
                "/swagger-ui/**", // Swagger UI
                "/webjars/**", // Swagger webjars
                "/swagger-ui.html" // Swagger UI HTML
            )
            .permitAll() // Bu endpoint'lere herkes erişebilir

            // Management endpoints (role + permission based)
            .requestMatchers("/api/v1/management/**")
            .hasAnyRole(ADMIN.name(), MANAGER.name())

            // Management GET endpoints (admin:read veya manager:read permission)
            .requestMatchers(GET, "/api/v1/management/**")
            .hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())

            // Management POST endpoints (admin:create veya manager:create permission)
            .requestMatchers(POST, "/api/v1/management/**")
            .hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())

            // Management PUT endpoints (admin:update veya manager:update permission)
            .requestMatchers(PUT, "/api/v1/management/**")
            .hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())

            // Management DELETE endpoints (admin:delete veya manager:delete permission)
            .requestMatchers(DELETE, "/api/v1/management/**")
            .hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())

            // Admin endpoints (@PreAuthorize annotation kullanılır, burada tanımlanmaz)
            // .requestMatchers("/api/v1/admin/**").hasRole(ADMIN.name())

            // Diğer tüm endpoint'ler authenticated user'lar tarafından erişilebilir
            .anyRequest()
            .authenticated())

        // Session management (STATELESS: server-side session oluşturulmaz)
        .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))

        // Authentication provider (ApplicationConfig'de tanımlanan provider)
        .authenticationProvider(authenticationProvider)

        // JWT filter (UsernamePasswordAuthenticationFilter'dan önce çalışır)
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)

        // Logout handling
        .logout(logout -> logout
            // Logout URL
            .logoutUrl("/api/v1/auth/logout")

            // Logout handler (LogoutService: token'ı revoke eder)
            .addLogoutHandler(logoutHandler)

            // Logout success handler (SecurityContext temizle)
            .logoutSuccessHandler(
                (request, response, authentication) -> SecurityContextHolder.clearContext()));

    SecurityFilterChain filterChain = http.build();
    System.out.println("=== SECURITY FILTER CHAIN ===");
    filterChain.getFilters()
        .forEach(filter -> System.out.println(filter.getClass().getSimpleName()));

    return filterChain;
  }
}