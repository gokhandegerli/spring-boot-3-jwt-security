package com.degerli.security.auditing;

import com.degerli.security.config.ApplicationConfig;
import com.degerli.security.user.User;
import java.util.Optional;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * ApplicationAuditAware - JPA Auditing için Current User Provider
 *
 * <p><b>NE:</b> JPA Auditing için current user bilgisini sağlar.
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @CreatedBy ve @LastModifiedBy annotation'ları için kullanılır.</p>
 *
 * <p><b>NEDEN:</b>
 * JPA Auditing, entity'leri oluşturan ve güncelleyen kullanıcıyı otomatik olarak
 * kaydetmek için AuditorAware interface'ini kullanır. Bu class, SecurityContext'ten
 * current user'ı alır ve ID'sini döner.
 * </p>
 *
 * <p><b>NASIL:</b>
 *
 * <b>1. JPA AUDITING ACTIVATION:</b>
 * ApplicationConfig'de AuditorAware bean tanımlanır:
 * <pre>
 * @Bean
 * public AuditorAware<Integer> auditorAware() {
 *     return new ApplicationAuditAware();
 * }
 * </pre>
 * <p>
 * Main class'ta @EnableJpaAuditing annotation eklenir:
 * <pre>
 * @EnableJpaAuditing(auditorAwareRef = "auditorAware")
 * </pre>
 *
 * <b>2. ENTITY'DE KULLANIM:</b>
 * <pre>
 * @Entity
 * @EntityListeners(AuditingEntityListener.class)
 * public class Book {
 *     @CreatedDate
 *     private LocalDateTime createdDate;
 *
 *     @LastModifiedDate
 *     private LocalDateTime lastModifiedDate;
 *
 *     @CreatedBy
 *     private Integer createdBy; // Otomatik olarak current user ID'si yazılır
 *
 *     @LastModifiedBy
 *     private Integer lastModifiedBy; // Otomatik olarak current user ID'si yazılır
 * }
 * </pre>
 *
 * <b>3. CURRENT USER ALMA:</b>
 * - SecurityContextHolder.getContext().getAuthentication() ile Authentication alınır
 * - Authentication null değilse ve AnonymousAuthenticationToken değilse
 * - Authentication.getPrincipal() ile User object alınır
 * - User.getId() ile user ID'si döner
 * - User yoksa Optional.empty() döner
 * </p>
 *
 * <p><b>AUTHENTICATION TYPES:</b>
 *
 * <b>1. Authenticated User:</b>
 * - Authentication != null
 * - Authentication.isAuthenticated() == true
 * - Principal: User object
 *
 * <b>2. Anonymous User:</b>
 * - Authentication instanceof AnonymousAuthenticationToken
 * - Principal: "anonymousUser" (String)
 *
 * <b>3. No Authentication:</b>
 * - Authentication == null
 * - SecurityContext boş
 * </p>
 *
 * <p><b>KULLANIM ÖRNEĞİ:</b>
 * <pre>
 * // 1. USER LOGIN YAPAR
 * POST /api/v1/auth/authenticate
 * {
 *   "email": "gokhan@mail.com",
 *   "password": "password"
 * }
 * Response: { "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }
 *
 * // 2. USER YENİ KİTAP OLUŞTURUR
 * POST /api/v1/books
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * {
 *   "author": "Gokhan Degerli",
 *   "isbn": "978-3-16-148410-0"
 * }
 *
 * // 3. JPA AUDITING OTOMATIK OLARAK ÇALIŞIR
 * // Book entity'si kaydedilirken:
 * // - createdDate: 2024-01-15 10:30:00
 * // - lastModifiedDate: 2024-01-15 10:30:00
 * // - createdBy: 1 (current user ID)
 * // - lastModifiedBy: 1 (current user ID)
 *
 * // 4. USER KİTABI GÜNCELLER
 * PUT /api/v1/books/1
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * {
 *   "author": "Gokhan Degerli Updated",
 *   "isbn": "978-3-16-148410-0"
 * }
 *
 * // 5. JPA AUDITING OTOMATIK OLARAK GÜNCELLER
 * // Book entity'si güncellenirken:
 * // - createdDate: 2024-01-15 10:30:00 (değişmez)
 * // - lastModifiedDate: 2024-01-15 11:00:00 (güncellenir)
 * // - createdBy: 1 (değişmez)
 * // - lastModifiedBy: 1 (güncellenir)
 * </pre>
 * </p>
 *
 * <p><b>SECURITY CONTEXT FLOW:</b>
 * 1. Request gelir (JWT token ile)
 * 2. JwtAuthenticationFilter token'ı validate eder
 * 3. SecurityContext'e Authentication object set edilir
 * 4. Controller method çağrılır
 * 5. Service method çağrılır
 * 6. Repository.save() çağrılır
 * 7. JPA Auditing, AuditorAware.getCurrentAuditor() çağırır
 * 8. SecurityContext'ten current user alınır
 * 9. User ID'si @CreatedBy ve @LastModifiedBy field'larına yazılır
 * 10. Entity DB'ye kaydedilir
 * </p>
 *
 * <p><b>ANONYMOUS USER HANDLING:</b>
 * Anonymous user için Optional.empty() döner.
 * Bu durumda @CreatedBy ve @LastModifiedBy field'ları null olur.
 *
 * <b>TODO:</b>
 * - Anonymous user için default value ekle (örn: -1 veya 0)
 * - System user için özel handling ekle (örn: scheduled job'lar için)
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Anonymous user için default value ekle
 * - System user için özel handling ekle
 * - Logging ekle (audit trail için)
 * - Exception handling ekle
 * </p>
 * @see AuditorAware Spring Data JPA auditing interface
 * @see ApplicationConfig AuditorAware bean tanımı
 * @see User User entity
 */
public class ApplicationAuditAware implements AuditorAware<Integer> {

  /**
   * Current user'ın ID'sini döner
   *
   * <p><b>NE:</b> JPA Auditing için current user ID'sini sağlar.</p>
   *
   * <p><b>NASIL:</b>
   * 1. SecurityContextHolder.getContext().getAuthentication() ile Authentication alınır
   * 2. Authentication null kontrolü yapılır
   * 3. Authentication.isAuthenticated() kontrolü yapılır
   * 4. AnonymousAuthenticationToken kontrolü yapılır (anonymous user değilse)
   * 5. Authentication.getPrincipal() ile User object alınır
   * 6. User.getId() ile user ID'si döner
   * 7. User yoksa Optional.empty() döner
   * </p>
   *
   * <p><b>RETURN VALUE:</b>
   * - Optional<Integer>: Current user ID'si (varsa)
   * - Optional.empty(): User yoksa veya anonymous user ise
   * </p>
   *
   * <p><b>AUTHENTICATION KONTROLÜ:</b>
   *
   * <b>1. authentication != null:</b>
   * - SecurityContext'te Authentication var mı?
   *
   * <b>2. authentication.isAuthenticated():</b>
   * - User authenticated mi?
   *
   * <b>3. !(authentication instanceof AnonymousAuthenticationToken):</b>
   * - User anonymous değil mi?
   * - Anonymous user: Spring Security'nin default user'ı (authentication gerektirmeyen
   * endpoint'ler için)
   * </p>
   *
   * <p><b>PRINCIPAL CASTING:</b>
   * <pre>
   * User userPrincipal = (User) authentication.getPrincipal();
   * </pre>
   * <p>
   * - Principal: Authentication object'in içindeki user bilgisi
   * - JwtAuthenticationFilter'da User object set edilir
   * - Bu yüzden (User) casting yapılabilir
   * </p>
   *
   * <p><b>ÖRNEK SENARYOLAR:</b>
   *
   * <b>1. Authenticated User:</b>
   * - Authentication != null
   * - isAuthenticated() == true
   * - Principal: User object
   * - Return: Optional.of(user.getId())
   *
   * <b>2. Anonymous User:</b>
   * - Authentication instanceof AnonymousAuthenticationToken
   * - Return: Optional.empty()
   *
   * <b>3. No Authentication:</b>
   * - Authentication == null
   * - Return: Optional.empty()
   * </p>
   *
   * <p><b>TODO:</b>
   * - Anonymous user için default value döndür (örn: Optional.of(-1))
   * - System user için özel handling ekle
   * - Exception handling ekle (ClassCastException)
   * </p>
   *
   * @return Current user ID (Optional)
   */
  @Override
  public Optional<Integer> getCurrentAuditor() {
    // SecurityContext'ten Authentication al
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    // Authentication kontrolü
    if (authentication == null || !authentication.isAuthenticated()
        || authentication instanceof AnonymousAuthenticationToken) {
      // User yok veya anonymous user -> Optional.empty() döner
      return Optional.empty();
    }

    // Principal'dan User object al (casting)
    User userPrincipal = (User) authentication.getPrincipal();

    // User ID'sini döner
    return Optional.ofNullable(userPrincipal.getId());
  }
}