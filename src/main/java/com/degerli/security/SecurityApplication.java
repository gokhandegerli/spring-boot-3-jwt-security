package com.degerli.security;

import com.degerli.security.auth.AuthenticationService;
import com.degerli.security.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import static com.degerli.security.user.Role.ADMIN;
import static com.degerli.security.user.Role.MANAGER;

/**
 * SecurityApplication - Spring Boot Main Application Class
 *
 * <p><b>NE:</b> Spring Boot uygulamasının başlangıç noktası.
 * Application'ı başlatır, JPA Auditing'i enable eder, demo user'ları oluşturur.</p>
 *
 * <p><b>NEDEN:</b>
 * - Spring Boot uygulamasını başlatmak
 * - Component scanning yapmak (@Component, @Service, @Repository, vb.)
 * - Auto-configuration yapmak (Spring Boot'un magic'i)
 * - JPA Auditing'i enable etmek (@CreatedBy, @LastModifiedBy için)
 * - Demo user'ları oluşturmak (test için)
 * </p>
 *
 * <p><b>NASIL:</b>
 *
 * <b>1. @SpringBootApplication:</b>
 * Aşağıdaki 3 annotation'ı içerir:
 * - @Configuration: Spring configuration class
 * - @EnableAutoConfiguration: Spring Boot auto-configuration
 * - @ComponentScan: Component scanning (current package ve alt package'lar)
 *
 * <b>2. @EnableJpaAuditing:</b>
 * - JPA Auditing'i enable eder
 * - @CreatedDate, @LastModifiedDate, @CreatedBy, @LastModifiedBy annotation'larını aktif eder
 * - auditorAwareRef: AuditorAware bean'in adı (ApplicationConfig'de tanımlı)
 *
 * <b>3. SpringApplication.run():</b>
 * - Spring Boot uygulamasını başlatır
 * - Embedded Tomcat server'ı başlatır
 * - Application context'i oluşturur
 * - Bean'leri initialize eder
 * - Auto-configuration yapar
 *
 * <b>4. CommandLineRunner Bean:</b>
 * - Application başladıktan sonra çalışır
 * - Demo user'ları oluşturur (ADMIN ve MANAGER)
 * - Test için kullanılır
 * </p>
 *
 * <p><b>APPLICATION STARTUP FLOW:</b>
 * 1. main() method çağrılır
 * 2. SpringApplication.run() çağrılır
 * 3. Spring Boot auto-configuration başlar
 * 4. Component scanning yapılır
 * 5. Bean'ler oluşturulur ve inject edilir
 * 6. Database connection kurulur
 * 7. JPA entity'ler initialize edilir
 * 8. Embedded Tomcat server başlatılır
 * 9. CommandLineRunner bean'leri çalıştırılır (demo user'lar oluşturulur)
 * 10. Application hazır hale gelir
 * 11. Log: "Started SecurityApplication in X seconds"
 * </p>
 *
 * <p><b>DEMO USERS:</b>
 *
 * <b>1. ADMIN USER:</b>
 * - Email: admin@mail.com
 * - Password: password
 * - Role: ADMIN
 * - Permissions: admin:read, admin:create, admin:update, admin:delete
 *
 * <b>2. MANAGER USER:</b>
 * - Email: manager@mail.com
 * - Password: password
 * - Role: MANAGER
 * - Permissions: manager:read, manager:create, manager:update, manager:delete
 * </p>
 *
 * <p><b>COMMANDLINERUNNER NEDİR:</b>
 * - Spring Boot'un sağladığı bir interface
 * - Application başladıktan sonra çalışır
 * - run() method'u implement edilir
 * - Database seeding, initial data loading için kullanılır
 * - Lambda expression ile kullanılabilir
 * </p>
 *
 * <p><b>KULLANIM ÖRNEĞİ:</b>
 * <pre>
 * // 1. APPLICATION BAŞLAT
 * mvn spring-boot:run
 *
 * // 2. DEMO USER'LAR OTOMATIK OLUŞTURULUR
 * // Log: "Admin user created"
 * // Log: "Manager user created"
 *
 * // 3. ADMIN USER İLE LOGIN YAP
 * POST /api/v1/auth/authenticate
 * {
 *   "email": "admin@mail.com",
 *   "password": "password"
 * }
 * Response: { "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }
 *
 * // 4. ADMIN ENDPOINT'E ERİŞ
 * GET /api/v1/admin
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * Response: 200 OK
 * "GET:: admin controller"
 *
 * // 5. MANAGER USER İLE LOGIN YAP
 * POST /api/v1/auth/authenticate
 * {
 *   "email": "manager@mail.com",
 *   "password": "password"
 * }
 * Response: { "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }
 *
 * // 6. MANAGEMENT ENDPOINT'E ERİŞ
 * GET /api/v1/management
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * Response: 200 OK
 * "GET:: management controller"
 * </pre>
 * </p>
 *
 * <p><b>JPA AUDITING CONFIGURATION:</b>
 *
 * <b>@EnableJpaAuditing(auditorAwareRef = "auditorAware"):</b>
 * - JPA Auditing'i enable eder
 * - auditorAwareRef: AuditorAware bean'in adı
 * - ApplicationConfig'de tanımlı:
 * <pre>
 * @Bean
 * public AuditorAware<Integer> auditorAware() {
 *     return new ApplicationAuditAware();
 * }
 * </pre>
 *
 * <b>AUDITING ANNOTATIONS:</b>
 * - @CreatedDate: Entity oluşturulma tarihi (otomatik)
 * - @LastModifiedDate: Entity güncellenme tarihi (otomatik)
 * - @CreatedBy: Entity'yi oluşturan user ID (otomatik)
 * - @LastModifiedBy: Entity'yi güncelleyen user ID (otomatik)
 * </p>
 *
 * <p><b>EMBEDDED TOMCAT:</b>
 * - Spring Boot, embedded Tomcat server ile gelir
 * - External Tomcat'e deploy etmeye gerek yok
 * - Default port: 8080
 * - application.yml'de değiştirilebilir:
 * <pre>
 * server:
 *   port: 9090
 * </pre>
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Demo user'ları sadece dev profile'da oluştur (production'da oluşturma)
 * - Demo user'ları externalize et (application.yml)
 * - Database migration tool kullan (Flyway, Liquibase)
 * - Health check endpoint ekle (Spring Boot Actuator)
 * - Metrics ekle (Prometheus, Grafana)
 * - Logging configuration ekle (Logback, SLF4J)
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see SpringBootApplication Spring Boot main annotation
 * @see EnableJpaAuditing JPA Auditing annotation
 * @see CommandLineRunner Application startup hook
 */
@SpringBootApplication // Spring Boot main annotation
@EnableJpaAuditing(auditorAwareRef = "auditorAware")
// JPA Auditing enable (AuditorAware bean adı)
public class SecurityApplication {

  /**
   * Main method - Application başlangıç noktası
   *
   * <p><b>NE:</b> Spring Boot uygulamasını başlatır.</p>
   *
   * <p><b>NASIL:</b>
   * 1. SpringApplication.run() çağrılır
   * 2. SecurityApplication.class: Main class
   * 3. args: Command line arguments
   * 4. Spring Boot auto-configuration başlar
   * 5. Application context oluşturulur
   * 6. Bean'ler initialize edilir
   * 7. Embedded Tomcat server başlatılır
   * 8. Application hazır hale gelir
   * </p>
   *
   * <p><b>COMMAND LINE ARGUMENTS:</b>
   * <pre>
   * // Custom port ile başlat
   * java -jar security-0.0.1-SNAPSHOT.jar --server.port=9090
   *
   * // Custom profile ile başlat
   * java -jar security-0.0.1-SNAPSHOT.jar --spring.profiles.active=prod
   *
   * // Custom property ile başlat
   * java -jar security-0.0.1-SNAPSHOT.jar --application.jwt.secret-key=myCustomSecret
   * </pre>
   * </p>
   *
   * @param args Command line arguments
   */
  public static void main(String[] args) {
    // Spring Boot uygulamasını başlat
    SpringApplication.run(SecurityApplication.class, args);
  }

  /**
   * CommandLineRunner Bean - Demo user'ları oluşturur
   *
   * <p><b>NE:</b> Application başladıktan sonra demo user'ları oluşturur.</p>
   *
   * <p><b>NEDEN:</b>
   * Test için ADMIN ve MANAGER user'ları gereklidir.
   * Her application başlatıldığında otomatik olarak oluşturulur.
   * </p>
   *
   * <p><b>NASIL:</b>
   * 1. Application başlar
   * 2. Tüm bean'ler initialize edilir
   * 3. CommandLineRunner bean'leri çalıştırılır
   * 4. AuthenticationService.register() çağrılır (ADMIN user)
   * 5. AuthenticationService.register() çağrılır (MANAGER user)
   * 6. Demo user'lar DB'ye kaydedilir
   * </p>
   *
   * <p><b>LAMBDA EXPRESSION:</b>
   * <pre>
   * args -> {
   *     // Code here
   * }
   * </pre>
   * <p>
   * Bu lambda expression şuna eşittir:
   * <pre>
   * new CommandLineRunner() {
   *     @Override
   *     public void run(String... args) throws Exception {
   *         // Code here
   *     }
   * }
   * </pre>
   * </p>
   *
   * <p><b>ADMIN USER:</b>
   * - Firstname: Admin
   * - Lastname: Admin
   * - Email: admin@mail.com
   * - Password: password (BCrypt ile hash'lenir)
   * - Role: ADMIN
   * - Permissions: admin:read, admin:create, admin:update, admin:delete
   * </p>
   *
   * <p><b>MANAGER USER:</b>
   * - Firstname: Manager
   * - Lastname: Manager
   * - Email: manager@mail.com
   * - Password: password (BCrypt ile hash'lenir)
   * - Role: MANAGER
   * - Permissions: manager:read, manager:create, manager:update, manager:delete
   * </p>
   *
   * <p><b>DUPLICATE USER HANDLING:</b>
   * Eğer user zaten varsa (email duplicate), exception fırlatılır.
   *
   * <b>TODO:</b>
   * - Duplicate user kontrolü ekle (exception yerine log)
   * - Demo user'ları sadece dev profile'da oluştur
   * - Demo user'ları externalize et (application.yml)
   * </p>
   *
   * <p><b>TODO İYİLEŞTİRMELER:</b>
   * - @Profile("dev") ekle (sadece dev profile'da çalışsın)
   * - Duplicate user kontrolü ekle
   * - Demo user'ları application.yml'den oku
   * - Database migration tool kullan (Flyway, Liquibase)
   * </p>
   *
   * @param service AuthenticationService (user registration için)
   * @return CommandLineRunner instance
   */
  @Bean
  public CommandLineRunner commandLineRunner(AuthenticationService service) {
    // Lambda expression: Application başladıktan sonra çalışır
    return args -> {
      // ADMIN USER OLUŞTUR
      var admin = RegisterRequest.builder()
          .firstname("Admin")
          .lastname("Admin")
          .email("admin@mail.com")
          .password("password") // BCrypt ile hash'lenecek
          .role(ADMIN) // ADMIN rolü
          .build();

      // ADMIN user'ı kaydet
      System.out.println("Admin token: " + service.register(admin).getAccessToken());

      // MANAGER USER OLUŞTUR
      var manager = RegisterRequest.builder()
          .firstname("Manager")
          .lastname("Manager")
          .email("manager@mail.com")
          .password("password") // BCrypt ile hash'lenecek
          .role(MANAGER) // MANAGER rolü
          .build();

      // MANAGER user'ı kaydet
      System.out.println("Manager token: " + service.register(manager).getAccessToken());
    };
  }
}