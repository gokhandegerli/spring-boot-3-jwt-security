package com.degerli.security.config;

import com.degerli.security.auditing.ApplicationAuditAware;
import com.degerli.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * ApplicationConfig - Spring Security ve Application Bean Configuration
 *
 * <p><b>NE:</b> Spring Security için gerekli bean'leri tanımlar.
 * Authentication, password encoding, user details service gibi core bean'leri sağlar.</p>
 *
 * <p><b>NEDEN:</b>
 * - Spring Security'nin çalışması için gerekli bean'leri merkezi bir yerde tanımlamak
 * - Dependency injection için bean'leri Spring context'e kaydetmek
 * - Custom authentication logic sağlamak
 * - Password encoding stratejisini belirlemek
 * - Auditing için AuditorAware bean'i sağlamak
 * </p>
 *
 * <p><b>NASIL:</b>
 *
 * <b>1. UserDetailsService Bean:</b>
 * - Spring Security'nin kullanıcı bilgilerini yüklemek için kullandığı servis
 * - Email ile kullanıcı bulur (username yerine email kullanılır)
 * - UserRepository.findByEmail() çağrılır
 * - Kullanıcı bulunamazsa UsernameNotFoundException fırlatılır
 *
 * <b>2. AuthenticationProvider Bean:</b>
 * - Authentication işlemini gerçekleştiren provider
 * - DaoAuthenticationProvider kullanılır (DB'den kullanıcı bilgilerini alır)
 * - UserDetailsService ve PasswordEncoder inject edilir
 * - Login sırasında kullanıcı doğrulaması yapar
 *
 * <b>3. AuthenticationManager Bean:</b>
 * - Authentication işlemini yöneten manager
 * - AuthenticationController'da kullanılır (login endpoint'i)
 * - AuthenticationConfiguration'dan alınır
 *
 * <b>4. PasswordEncoder Bean:</b>
 * - Password'leri hash'lemek için kullanılan encoder
 * - BCryptPasswordEncoder kullanılır (industry standard)
 * - Register ve password change işlemlerinde kullanılır
 *
 * <b>5. AuditorAware Bean:</b>
 * - JPA Auditing için current user bilgisini sağlar
 * - @CreatedBy ve @LastModifiedBy annotation'ları için kullanılır
 * - ApplicationAuditAware implementation'ı kullanılır
 * </p>
 *
 * <p><b>BEAN LIFECYCLE:</b>
 * 1. Spring Boot başlatılır
 * 2. @Configuration class'ları taranır
 * 3. @Bean method'ları çağrılır
 * 4. Bean'ler Spring context'e kaydedilir
 * 5. Dependency injection yapılır
 * 6. Application hazır hale gelir
 * </p>
 *
 * <p><b>KULLANIM ÖRNEĞİ:</b>
 * <pre>
 * // 1. UserDetailsService kullanımı (Spring Security tarafından otomatik)
 * // Login sırasında:
 * UserDetails user = userDetailsService.loadUserByUsername("admin@mail.com");
 *
 * // 2. PasswordEncoder kullanımı
 * String hashedPassword = passwordEncoder.encode("password123");
 * boolean matches = passwordEncoder.matches("password123", hashedPassword);
 *
 * // 3. AuthenticationManager kullanımı (AuthenticationController'da)
 * Authentication auth = authenticationManager.authenticate(
 *     new UsernamePasswordAuthenticationToken(email, password)
 * );
 * </pre>
 * </p>
 *
 * <p><b>SECURITY BEST PRACTICES:</b>
 * - BCrypt kullan (MD5, SHA1 kullanma)
 * - Password strength validation ekle
 * - Rate limiting ekle (brute force attack'lere karşı)
 * - Account locking ekle (çok fazla başarısız login denemesi)
 * - Password history tut (aynı password'ü tekrar kullanmayı engelle)
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - BCrypt strength parametresini externalize et (application.yml)
 * - Custom UserDetailsService implementation ekle (daha fazla kontrol)
 * - Failed login attempt tracking ekle
 * - Account locking mechanism ekle
 * - Password policy configuration ekle
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see UserDetailsService Spring Security user details service
 * @see AuthenticationProvider Authentication provider interface
 * @see AuthenticationManager Authentication manager interface
 * @see PasswordEncoder Password encoder interface
 * @see AuditorAware JPA auditing interface
 */
@Configuration // Spring configuration class
@RequiredArgsConstructor // Lombok: final field için constructor
public class ApplicationConfig {

  /**
   * User repository
   *
   * <p>Kullanıcı bilgilerini DB'den almak için kullanılır.</p>
   */
  private final UserRepository repository;

  /**
   * UserDetailsService Bean
   *
   * <p><b>NE:</b> Spring Security'nin kullanıcı bilgilerini yüklemek için kullandığı servis
   * .</p>
   *
   * <p><b>NEDEN:</b>
   * Spring Security, authentication sırasında kullanıcı bilgilerini yüklemek için
   * UserDetailsService interface'ini kullanır. Bu bean, email ile kullanıcı bulur.
   * </p>
   *
   * <p><b>NASIL:</b>
   * 1. Spring Security authentication sırasında bu method'u çağırır
   * 2. Email (username) parameter olarak gelir
   * 3. UserRepository.findByEmail() ile kullanıcı aranır
   * 4. Kullanıcı bulunursa UserDetails döner
   * 5. Kullanıcı bulunamazsa UsernameNotFoundException fırlatılır
   * </p>
   *
   * <p><b>LAMBDA EXPRESSION:</b>
   * <pre>
   * username -> repository.findByEmail(username)
   *     .orElseThrow(() -> new UsernameNotFoundException("User not found"))
   * </pre>
   * <p>
   * Bu lambda expression şuna eşittir:
   * <pre>
   * new UserDetailsService() {
   *     @Override
   *     public UserDetails loadUserByUsername(String username) {
   *         return repository.findByEmail(username)
   *             .orElseThrow(() -> new UsernameNotFoundException("User not found"));
   *     }
   * }
   * </pre>
   * </p>
   *
   * <p><b>NEDEN EMAIL KULLANILIYOR:</b>
   * - Modern uygulamalarda email unique identifier olarak kullanılır
   * - Username yerine email daha user-friendly
   * - Email ile password reset daha kolay
   * </p>
   *
   * <p><b>EXCEPTION HANDLING:</b>
   * UsernameNotFoundException fırlatılırsa Spring Security otomatik olarak
   * 401 Unauthorized veya 403 Forbidden döner.
   * </p>
   *
   * <p><b>TODO:</b>
   * - Custom exception message ekle (security için generic mesaj kullan)
   * - Logging ekle (failed login attempt tracking)
   * - Cache ekle (aynı kullanıcı için tekrar DB'ye gitme)
   * </p>
   *
   * @return UserDetailsService implementation
   * @throws UsernameNotFoundException Kullanıcı bulunamazsa
   */
  @Bean
  public UserDetailsService userDetailsService() {
    // Lambda expression: username (email) alır, UserDetails döner
    return username -> repository.findByEmail(username)
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
  }

  /**
   * AuthenticationProvider Bean
   *
   * <p><b>NE:</b> Authentication işlemini gerçekleştiren provider.</p>
   *
   * <p><b>NEDEN:</b>
   * Spring Security, authentication sırasında AuthenticationProvider kullanır.
   * DaoAuthenticationProvider, DB'den kullanıcı bilgilerini alır ve doğrular.
   * </p>
   *
   * <p><b>NASIL:</b>
   * 1. DaoAuthenticationProvider instance'ı oluşturulur
   * 2. UserDetailsService inject edilir (kullanıcı bilgilerini yüklemek için)
   * 3. PasswordEncoder inject edilir (password doğrulamak için)
   * 4. Spring Security bu provider'ı authentication sırasında kullanır
   * </p>
   *
   * <p><b>AUTHENTICATION FLOW:</b>
   * 1. User login yapar (email + password)
   * 2. AuthenticationProvider.authenticate() çağrılır
   * 3. UserDetailsService.loadUserByUsername() ile kullanıcı yüklenir
   * 4. PasswordEncoder.matches() ile password doğrulanır
   * 5. Password doğruysa Authentication object döner
   * 6. Password yanlışsa BadCredentialsException fırlatılır
   * </p>
   *
   * <p><b>ALTERNATIF PROVIDER'LAR:</b>
   * - LdapAuthenticationProvider: LDAP authentication
   * - JwtAuthenticationProvider: JWT authentication
   * - OAuth2AuthenticationProvider: OAuth2 authentication
   * </p>
   *
   * <p><b>TODO:</b>
   * - Custom AuthenticationProvider implementation ekle (daha fazla kontrol)
   * - Failed login attempt tracking ekle
   * - Account locking ekle
   * </p>
   *
   * @return DaoAuthenticationProvider instance
   */
  @Bean
  public AuthenticationProvider authenticationProvider() {
    // DaoAuthenticationProvider: DB'den kullanıcı bilgilerini alır
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

    // UserDetailsService inject et (kullanıcı bilgilerini yüklemek için)
    authProvider.setUserDetailsService(userDetailsService());

    // PasswordEncoder inject et (password doğrulamak için)
    authProvider.setPasswordEncoder(passwordEncoder());

    return authProvider;
  }

  /**
   * AuditorAware Bean
   *
   * <p><b>NE:</b> JPA Auditing için current user bilgisini sağlar.</p>
   *
   * <p><b>NEDEN:</b>
   * JPA Auditing, @CreatedBy ve @LastModifiedBy annotation'ları için
   * current user bilgisine ihtiyaç duyar. Bu bean, SecurityContext'ten
   * current user'ı alır.
   * </p>
   *
   * <p><b>NASIL:</b>
   * 1. ApplicationAuditAware.getCurrentAuditor() çağrılır
   * 2. SecurityContext'ten current user alınır
   * 3. User'ın ID'si döner
   * 4. JPA Auditing bu ID'yi @CreatedBy ve @LastModifiedBy field'larına yazar
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * @Entity
   * @EntityListeners(AuditingEntityListener.class)
   * public class Book {
   *     @CreatedBy
   *     private Integer createdBy; // Otomatik olarak current user ID'si yazılır
   *
   *     @LastModifiedBy
   *     private Integer lastModifiedBy; // Otomatik olarak current user ID'si yazılır
   * }
   * </pre>
   * </p>
   *
   * <p><b>TODO:</b>
   * - Anonymous user için default value ekle
   * - System user için özel handling ekle
   * </p>
   *
   * @return ApplicationAuditAware instance
   * @see ApplicationAuditAware Current user provider
   */
  @Bean
  public AuditorAware<Integer> auditorAware() {
    return new ApplicationAuditAware();
  }

  /**
   * AuthenticationManager Bean
   *
   * <p><b>NE:</b> Authentication işlemini yöneten manager.</p>
   *
   * <p><b>NEDEN:</b>
   * AuthenticationController'da login endpoint'i için AuthenticationManager
   * gereklidir. Bu bean, AuthenticationConfiguration'dan alınır.
   * </p>
   *
   * <p><b>NASIL:</b>
   * 1. AuthenticationConfiguration.getAuthenticationManager() çağrılır
   * 2. Spring Security'nin default AuthenticationManager'ı döner
   * 3. Bu manager, AuthenticationProvider'ları kullanarak authentication yapar
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * // AuthenticationController.authenticate() method'unda:
   * authenticationManager.authenticate(
   *     new UsernamePasswordAuthenticationToken(
   *         request.getEmail(),
   *         request.getPassword()
   *     )
   * );
   * </pre>
   * </p>
   *
   * <p><b>EXCEPTION HANDLING:</b>
   * - BadCredentialsException: Yanlış password
   * - UsernameNotFoundException: Kullanıcı bulunamadı
   * - DisabledException: Kullanıcı disabled
   * - LockedException: Kullanıcı locked
   * </p>
   *
   * @param config AuthenticationConfiguration
   * @return AuthenticationManager instance
   * @throws Exception AuthenticationManager alınamazsa
   */
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
      throws Exception {
    // AuthenticationConfiguration'dan AuthenticationManager al
    return config.getAuthenticationManager();
  }

  /**
   * PasswordEncoder Bean
   *
   * <p><b>NE:</b> Password'leri hash'lemek için kullanılan encoder.</p>
   *
   * <p><b>NEDEN:</b>
   * Password'ler plain text olarak saklanmamalıdır. BCrypt, industry standard
   * bir hashing algoritmasıdır ve brute force attack'lere karşı dayanıklıdır.
   * </p>
   *
   * <p><b>NASIL:</b>
   * 1. BCryptPasswordEncoder instance'ı oluşturulur
   * 2. Register sırasında password hash'lenir: passwordEncoder.encode("password123")
   * 3. Login sırasında password doğrulanır: passwordEncoder.matches("password123",
   * hashedPassword)
   * </p>
   *
   * <p><b>BCRYPT ÖZELLİKLERİ:</b>
   * - Salt otomatik olarak eklenir (her hash farklıdır)
   * - Adaptive hashing (zaman içinde güçlendirilebilir)
   * - Brute force attack'lere karşı dayanıklı (yavaş hash)
   * - Industry standard (OWASP tarafından önerilir)
   * </p>
   *
   * <p><b>BCRYPT STRENGTH:</b>
   * Default strength: 10 (2^10 = 1024 round)
   * Daha yüksek strength daha güvenli ama daha yavaş.
   * <pre>
   * new BCryptPasswordEncoder(12) // 2^12 = 4096 round (daha güvenli)
   * </pre>
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * // 1. ENCODE (Register sırasında)
   * String hashedPassword = passwordEncoder.encode("password123");
   * // Output: $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
   *
   * // 2. MATCHES (Login sırasında)
   * boolean matches = passwordEncoder.matches("password123", hashedPassword);
   * // Output: true
   *
   * // 3. WRONG PASSWORD
   * boolean matches = passwordEncoder.matches("wrongpassword", hashedPassword);
   * // Output: false
   * </pre>
   * </p>
   *
   * <p><b>SECURITY WARNING:</b>
   * - MD5, SHA1 kullanma (deprecated, güvensiz)
   * - Plain text password saklama (asla!)
   * - Custom hashing algorithm kullanma (BCrypt kullan)
   * </p>
   *
   * <p><b>TODO:</b>
   * - BCrypt strength parametresini externalize et (application.yml)
   * - Password strength validation ekle (min 8 karakter, büyük harf, rakam, vb.)
   * - Password history tut (aynı password'ü tekrar kullanmayı engelle)
   * </p>
   *
   * @return BCryptPasswordEncoder instance
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    // BCryptPasswordEncoder: Industry standard password encoder
    return new BCryptPasswordEncoder();
  }
}