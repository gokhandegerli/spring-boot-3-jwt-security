package com.degerli.security.demo;

import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AdminController - Admin REST Controller
 *
 * <p><b>NE:</b> Admin rolüne özel endpoint'ler sağlar.
 * Sadece ADMIN rolüne sahip kullanıcılar erişebilir.</p>
 *
 * <p><b>NEDEN:</b>
 * - Role-based access control (RBAC) örneği göstermek
 * - Admin işlemleri için ayrı endpoint'ler sağlamak
 * - Method-level security (@PreAuthorize) kullanımını göstermek
 * </p>
 *
 * <p><b>ENDPOINT'LER:</b>
 *
 * <b>1. GET /api/v1/admin</b>
 * - Admin GET endpoint
 * - Response: "GET:: admin controller"
 * - Sadece ADMIN rolü erişebilir
 *
 * <b>2. POST /api/v1/admin</b>
 * - Admin POST endpoint
 * - Response: "POST:: admin controller"
 * - Sadece ADMIN rolü erişebilir
 *
 * <b>3. PUT /api/v1/admin</b>
 * - Admin PUT endpoint
 * - Response: "PUT:: admin controller"
 * - Sadece ADMIN rolü erişebilir
 *
 * <b>4. DELETE /api/v1/admin</b>
 * - Admin DELETE endpoint
 * - Response: "DELETE:: admin controller"
 * - Sadece ADMIN rolü erişebilir
 * </p>
 *
 * <p><b>SECURITY:</b>
 *
 * <b>@PreAuthorize("hasRole('ADMIN')"):</b>
 * - Method-level security annotation
 * - Method çağrılmadan önce authorization kontrolü yapar
 * - Sadece ADMIN rolüne sahip kullanıcılar erişebilir
 * - ADMIN rolü yoksa 403 Forbidden döner
 *
 * <b>ALTERNATIF YÖNTEM:</b>
 * SecurityConfiguration'da URL-based authorization:
 * <pre>
 * .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
 * </pre>
 *
 * <b>FARK:</b>
 * - @PreAuthorize: Method-level (daha granular)
 * - SecurityConfiguration: URL-level (daha genel)
 * </p>
 *
 * <p><b>@Hidden ANNOTATION:</b>
 * Swagger/OpenAPI documentation'dan gizler.
 * Bu endpoint'ler API documentation'da görünmez.
 * </p>
 *
 * <p><b>KULLANIM ÖRNEĞİ:</b>
 * <pre>
 * // 1. ADMIN kullanıcı ile login yap
 * POST /api/v1/auth/authenticate
 * {
 *   "email": "admin@mail.com",
 *   "password": "password"
 * }
 * Response: { "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }
 *
 * // 2. Token ile admin endpoint'e istek at
 * GET /api/v1/admin
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * Response: 200 OK
 * "GET:: admin controller"
 *
 * // 3. USER rolü ile istek at
 * GET /api/v1/admin
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (USER token)
 * Response: 403 Forbidden
 * </pre>
 * </p>
 *
 * <p><b>TEST SENARYOLARI:</b>
 * 1. ADMIN rolü ile istek at -> 200 OK
 * 2. USER rolü ile istek at -> 403 Forbidden
 * 3. MANAGER rolü ile istek at -> 403 Forbidden
 * 4. Token olmadan istek at -> 403 Forbidden
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Gerçek admin işlemleri ekle (user management, vb.)
 * - DTO kullan (String yerine JSON response)
 * - Exception handling ekle
 * - Audit logging ekle (kim ne zaman admin işlemi yaptı)
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see Role ADMIN rolü enum'u
 * @see SecurityConfiguration Security config
 */
@RestController // REST API controller
@RequestMapping("/api/v1/admin") // Base path: /api/v1/admin
@PreAuthorize("hasRole('ADMIN')") // Class-level: Tüm endpoint'ler ADMIN rolü gerektirir
@Hidden // Swagger/OpenAPI documentation'dan gizle
public class AdminController {

  /**
   * Admin GET endpoint
   *
   * <p><b>NE:</b> Admin GET işlemi için demo endpoint.</p>
   *
   * <p><b>HTTP METHOD:</b> GET</p>
   * <p><b>PATH:</b> /api/v1/admin</p>
   * <p><b>RESPONSE:</b> String (plain text)</p>
   * <p><b>AUTHORIZATION:</b> ADMIN rolü gerekli</p>
   *
   * <p><b>REQUEST ÖRNEĞİ:</b>
   * <pre>
   * GET /api/v1/admin
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (ADMIN token)
   * </pre>
   * </p>
   *
   * <p><b>RESPONSE ÖRNEĞİ:</b>
   * <pre>
   * 200 OK
   * "GET:: admin controller"
   * </pre>
   * </p>
   *
   * @return "GET:: admin controller" mesajı
   */
  @GetMapping
  @PreAuthorize("hasAuthority('admin:read')") // Method-level: admin:read permission gerekli
  public String get() {
    return "GET:: admin controller";
  }

  /**
   * Admin POST endpoint
   *
   * <p><b>NE:</b> Admin POST işlemi için demo endpoint.</p>
   *
   * <p><b>HTTP METHOD:</b> POST</p>
   * <p><b>PATH:</b> /api/v1/admin</p>
   * <p><b>RESPONSE:</b> String (plain text)</p>
   * <p><b>AUTHORIZATION:</b> ADMIN rolü + admin:create permission gerekli</p>
   *
   * <p><b>REQUEST ÖRNEĞİ:</b>
   * <pre>
   * POST /api/v1/admin
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (ADMIN token)
   * </pre>
   * </p>
   *
   * <p><b>RESPONSE ÖRNEĞİ:</b>
   * <pre>
   * 200 OK
   * "POST:: admin controller"
   * </pre>
   * </p>
   *
   * @return "POST:: admin controller" mesajı
   */
  @PostMapping
  @PreAuthorize("hasAuthority('admin:create')")
  // Method-level: admin:create permission gerekli
  public String post() {
    return "POST:: admin controller";
  }

  /**
   * Admin PUT endpoint
   *
   * <p><b>NE:</b> Admin PUT işlemi için demo endpoint.</p>
   *
   * <p><b>HTTP METHOD:</b> PUT</p>
   * <p><b>PATH:</b> /api/v1/admin</p>
   * <p><b>RESPONSE:</b> String (plain text)</p>
   * <p><b>AUTHORIZATION:</b> ADMIN rolü + admin:update permission gerekli</p>
   *
   * <p><b>REQUEST ÖRNEĞİ:</b>
   * <pre>
   * PUT /api/v1/admin
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (ADMIN token)
   * </pre>
   * </p>
   *
   * <p><b>RESPONSE ÖRNEĞİ:</b>
   * <pre>
   * 200 OK
   * "PUT:: admin controller"
   * </pre>
   * </p>
   *
   * @return "PUT:: admin controller" mesajı
   */
  @PutMapping
  @PreAuthorize("hasAuthority('admin:update')")
  // Method-level: admin:update permission gerekli
  public String put() {
    return "PUT:: admin controller";
  }

  /**
   * Admin DELETE endpoint
   *
   * <p><b>NE:</b> Admin DELETE işlemi için demo endpoint.</p>
   *
   * <p><b>HTTP METHOD:</b> DELETE</p>
   * <p><b>PATH:</b> /api/v1/admin</p>
   * <p><b>RESPONSE:</b> String (plain text)</p>
   * <p><b>AUTHORIZATION:</b> ADMIN rolü + admin:delete permission gerekli</p>
   *
   * <p><b>REQUEST ÖRNEĞİ:</b>
   * <pre>
   * DELETE /api/v1/admin
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (ADMIN token)
   * </pre>
   * </p>
   *
   * <p><b>RESPONSE ÖRNEĞİ:</b>
   * <pre>
   * 200 OK
   * "DELETE:: admin controller"
   * </pre>
   * </p>
   *
   * @return "DELETE:: admin controller" mesajı
   */
  @DeleteMapping
  @PreAuthorize("hasAuthority('admin:delete')")
  // Method-level: admin:delete permission gerekli
  public String delete() {
    return "DELETE:: admin controller";
  }
}