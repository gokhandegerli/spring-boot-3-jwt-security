package com.degerli.security.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Permission Enum - Detaylı Yetki Tanımları
 *
 * <p><b>NE:</b> Sistemdeki tüm permission'ları (yetkileri) tanımlayan enum.
 * Her permission bir String değer tutar ve Spring Security'de authority olarak kullanılır.</p>
 *
 * <p><b>NEDEN:</b>
 * - Fine-grained (detaylı) yetkilendirme için
 * - CRUD operasyonlarını ayrı ayrı kontrol etmek için
 * - Role'den bağımsız, permission-based authorization için
 * - Type-safe permission tanımları
 * </p>
 *
 * <p><b>NASIL KULLANILIR:</b>
 * <pre>
 * // Controller'da:
 * {@literal @}PreAuthorize("hasAuthority('admin:read')")
 * public String getAdminData() { ... }
 *
 * {@literal @}PreAuthorize("hasAuthority('admin:create')")
 * public String createAdminData() { ... }
 * </pre>
 * </p>
 *
 * <p><b>NAMING CONVENTION:</b>
 * - Format: {RESOURCE}:{ACTION}
 * - Örnekler: admin:read, management:create
 * - Küçük harf kullanılır (Spring Security convention)
 * </p>
 *
 * <p><b>PERMISSION GRUPLARI:</b>
 * - ADMIN_* : Admin panel işlemleri için
 * - MANAGER_* : Management panel işlemleri için
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see Role Permission'ları role'lere atayan enum
 */
@RequiredArgsConstructor // Lombok: final field için constructor oluşturur
public enum Permission {

  // ========== ADMIN PERMISSIONS ==========

  /**
   * Admin Read Permission
   *
   * <p><b>YETKİ:</b> Admin kaynaklarını okuma yetkisi</p>
   * <p><b>KULLANIM:</b> GET /api/v1/admin endpoint'i için</p>
   * <p><b>SAHİP ROLLER:</b> ADMIN</p>
   */
  ADMIN_READ("admin:read"),

  /**
   * Admin Update Permission
   *
   * <p><b>YETKİ:</b> Admin kaynaklarını güncelleme yetkisi</p>
   * <p><b>KULLANIM:</b> PUT /api/v1/admin endpoint'i için</p>
   * <p><b>SAHİP ROLLER:</b> ADMIN</p>
   */
  ADMIN_UPDATE("admin:update"),

  /**
   * Admin Create Permission
   *
   * <p><b>YETKİ:</b> Admin kaynakları oluşturma yetkisi</p>
   * <p><b>KULLANIM:</b> POST /api/v1/admin endpoint'i için</p>
   * <p><b>SAHİP ROLLER:</b> ADMIN</p>
   */
  ADMIN_CREATE("admin:create"),

  /**
   * Admin Delete Permission
   *
   * <p><b>YETKİ:</b> Admin kaynaklarını silme yetkisi</p>
   * <p><b>KULLANIM:</b> DELETE /api/v1/admin endpoint'i için</p>
   * <p><b>SAHİP ROLLER:</b> ADMIN</p>
   */
  ADMIN_DELETE("admin:delete"),

  // ========== MANAGER PERMISSIONS ==========

  /**
   * Manager Read Permission
   *
   * <p><b>YETKİ:</b> Management kaynaklarını okuma yetkisi</p>
   * <p><b>KULLANIM:</b> GET /api/v1/management endpoint'i için</p>
   * <p><b>SAHİP ROLLER:</b> ADMIN, MANAGER</p>
   */
  MANAGER_READ("management:read"),

  /**
   * Manager Update Permission
   *
   * <p><b>YETKİ:</b> Management kaynaklarını güncelleme yetkisi</p>
   * <p><b>KULLANIM:</b> PUT /api/v1/management endpoint'i için</p>
   * <p><b>SAHİP ROLLER:</b> ADMIN, MANAGER</p>
   */
  MANAGER_UPDATE("management:update"),

  /**
   * Manager Create Permission
   *
   * <p><b>YETKİ:</b> Management kaynakları oluşturma yetkisi</p>
   * <p><b>KULLANIM:</b> POST /api/v1/management endpoint'i için</p>
   * <p><b>SAHİP ROLLER:</b> ADMIN, MANAGER</p>
   */
  MANAGER_CREATE("management:create"),

  /**
   * Manager Delete Permission
   *
   * <p><b>YETKİ:</b> Management kaynaklarını silme yetkisi</p>
   * <p><b>KULLANIM:</b> DELETE /api/v1/management endpoint'i için</p>
   * <p><b>SAHİP ROLLER:</b> ADMIN, MANAGER</p>
   */
  MANAGER_DELETE("management:delete");

  /**
   * Permission'ın String değeri
   *
   * <p>Spring Security'de authority olarak kullanılan değer.
   * Örnek: "admin:read", "management:create"</p>
   *
   * <p>Lombok @Getter ile getter method otomatik oluşturulur.</p>
   */
  @Getter
  private final String permission;
}