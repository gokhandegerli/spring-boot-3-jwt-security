package com.degerli.security.demo;

import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * ManagementController - Management REST Controller
 *
 * <p><b>NE:</b> Manager rolüne özel endpoint'ler sağlar.
 * Sadece MANAGER ve ADMIN rollerine sahip kullanıcılar erişebilir.</p>
 *
 * <p><b>NEDEN:</b>
 * - Role-based ve permission-based access control örneği göstermek
 * - Manager işlemleri için ayrı endpoint'ler sağlamak
 * - SecurityConfiguration'da URL-based authorization kullanımını göstermek
 * </p>
 *
 * <p><b>ENDPOINT'LER:</b>
 *
 * <b>1. GET /api/v1/management</b>
 * - Management GET endpoint
 * - Response: "GET:: management controller"
 * - MANAGER ve ADMIN rolleri erişebilir
 *
 * <b>2. POST /api/v1/management</b>
 * - Management POST endpoint
 * - Response: "POST:: management controller"
 * - MANAGER ve ADMIN rolleri erişebilir
 *
 * <b>3. PUT /api/v1/management</b>
 * - Management PUT endpoint
 * - Response: "PUT:: management controller"
 * - MANAGER ve ADMIN rolleri erişebilir
 *
 * <b>4. DELETE /api/v1/management</b>
 * - Management DELETE endpoint
 * - Response: "DELETE:: management controller"
 * - MANAGER ve ADMIN rolleri erişebilir
 * </p>
 *
 * <p><b>SECURITY:</b>
 *
 * <b>SecurityConfiguration'da URL-based authorization:</b>
 * <pre>
 * .requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())
 * .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
 * .requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
 * .requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
 * .requestMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())
 * </pre>
 *
 * <b>FARK (AdminController ile):</b>
 * - AdminController: @PreAuthorize ile method-level security
 * - ManagementController: SecurityConfiguration ile URL-level security
 *
 * <b>HANGİSİ DAHA İYİ:</b>
 * - Method-level: Daha granular, daha esnek
 * - URL-level: Daha merkezi, daha kolay yönetim
 * </p>
 *
 * <p><b>@Hidden ANNOTATION:</b>
 * Swagger/OpenAPI documentation'dan gizler.
 * Bu endpoint'ler API documentation'da görünmez.
 * </p>
 *
 * <p><b>KULLANIM ÖRNEĞİ:</b>
 * <pre>
 * // 1. MANAGER kullanıcı ile login yap
 * POST /api/v1/auth/authenticate
 * {
 *   "email": "manager@mail.com",
 *   "password": "password"
 * }
 * Response: { "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }
 *
 * // 2. Token ile management endpoint'e istek at
 * GET /api/v1/management
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * Response: 200 OK
 * "GET:: management controller"
 *
 * // 3. USER rolü ile istek at
 * GET /api/v1/management
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (USER token)
 * Response: 403 Forbidden
 * </pre>
 * </p>
 *
 * <p><b>TEST SENARYOLARI:</b>
 * 1. MANAGER rolü ile istek at -> 200 OK
 * 2. ADMIN rolü ile istek at -> 200 OK
 * 3. USER rolü ile istek at -> 403 Forbidden
 * 4. Token olmadan istek at -> 403 Forbidden
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Gerçek management işlemleri ekle (report, analytics, vb.)
 * - DTO kullan (String yerine JSON response)
 * - Exception handling ekle
 * - Audit logging ekle
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see Role MANAGER rolü enum'u
 * @see Permission Management permission'ları
 * @see SecurityConfiguration Security config
 */
@RestController // REST API controller
@RequestMapping("/api/v1/management") // Base path: /api/v1/management
@Hidden // Swagger/OpenAPI documentation'dan gizle
public class ManagementController {

  /**
   * Management GET endpoint
   *
   * <p><b>NE:</b> Management GET işlemi için demo endpoint.</p>
   *
   * <p><b>HTTP METHOD:</b> GET</p>
   * <p><b>PATH:</b> /api/v1/management</p>
   * <p><b>RESPONSE:</b> String (plain text)</p>
   * <p><b>AUTHORIZATION:</b> MANAGER veya ADMIN rolü + READ permission gerekli</p>
   *
   * <p><b>SECURITY:</b>
   * SecurityConfiguration'da kontrol edilir:
   * <pre>
   * .requestMatchers(GET, "/api/v1/management/**")
   *     .hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
   * </pre>
   * </p>
   *
   * <p><b>REQUEST ÖRNEĞİ:</b>
   * <pre>
   * GET /api/v1/management
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (MANAGER token)
   * </pre>
   * </p>
   *
   * <p><b>RESPONSE ÖRNEĞİ:</b>
   * <pre>
   * 200 OK
   * "GET:: management controller"
   * </pre>
   * </p>
   *
   * @return "GET:: management controller" mesajı
   */
  @GetMapping
  public String get() {
    return "GET:: management controller";
  }

  /**
   * Management POST endpoint
   *
   * <p><b>NE:</b> Management POST işlemi için demo endpoint.</p>
   *
   * <p><b>HTTP METHOD:</b> POST</p>
   * <p><b>PATH:</b> /api/v1/management</p>
   * <p><b>RESPONSE:</b> String (plain text)</p>
   * <p><b>AUTHORIZATION:</b> MANAGER veya ADMIN rolü + CREATE permission gerekli</p>
   *
   * <p><b>SECURITY:</b>
   * SecurityConfiguration'da kontrol edilir:
   * <pre>
   * .requestMatchers(POST, "/api/v1/management/**")
   *     .hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
   * </pre>
   * </p>
   *
   * @return "POST:: management controller" mesajı
   */
  @PostMapping
  public String post() {
    return "POST:: management controller";
  }

  /**
   * Management PUT endpoint
   *
   * <p><b>NE:</b> Management PUT işlemi için demo endpoint.</p>
   *
   * <p><b>HTTP METHOD:</b> PUT</p>
   * <p><b>PATH:</b> /api/v1/management</p>
   * <p><b>RESPONSE:</b> String (plain text)</p>
   * <p><b>AUTHORIZATION:</b> MANAGER veya ADMIN rolü + UPDATE permission gerekli</p>
   *
   * <p><b>SECURITY:</b>
   * SecurityConfiguration'da kontrol edilir:
   * <pre>
   * .requestMatchers(PUT, "/api/v1/management/**")
   *     .hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
   * </pre>
   * </p>
   *
   * @return "PUT:: management controller" mesajı
   */
  @PutMapping
  public String put() {
    return "PUT:: management controller";
  }

  /**
   * Management DELETE endpoint
   *
   * <p><b>NE:</b> Management DELETE işlemi için demo endpoint.</p>
   *
   * <p><b>HTTP METHOD:</b> DELETE</p>
   * <p><b>PATH:</b> /api/v1/management</p>
   * <p><b>RESPONSE:</b> String (plain text)</p>
   * <p><b>AUTHORIZATION:</b> MANAGER veya ADMIN rolü + DELETE permission gerekli</p>
   *
   * <p><b>SECURITY:</b>
   * SecurityConfiguration'da kontrol edilir:
   * <pre>
   * .requestMatchers(DELETE, "/api/v1/management/**")
   *     .hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())
   * </pre>
   * </p>
   *
   * @return "DELETE:: management controller" mesajı
   */
  @DeleteMapping
  public String delete() {
    return "DELETE:: management controller";
  }
}