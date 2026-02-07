package com.degerli.security.user;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import static com.degerli.security.user.Permission.ADMIN_CREATE;
import static com.degerli.security.user.Permission.ADMIN_DELETE;
import static com.degerli.security.user.Permission.ADMIN_READ;
import static com.degerli.security.user.Permission.ADMIN_UPDATE;
import static com.degerli.security.user.Permission.MANAGER_CREATE;
import static com.degerli.security.user.Permission.MANAGER_DELETE;
import static com.degerli.security.user.Permission.MANAGER_READ;
import static com.degerli.security.user.Permission.MANAGER_UPDATE;

/**
 * Role Enum - Kullanıcı Rolleri ve Yetkileri
 *
 * <p><b>NE:</b> Sistemdeki kullanıcı rollerini ve her role ait permission'ları tanımlayan
 * enum.
 * Spring Security'nin role-based ve permission-based authorization mekanizmasında
 * kullanılır.</p>
 *
 * <p><b>NEDEN:</b>
 * - Role-Based Access Control (RBAC) implementasyonu
 * - Her rolün farklı yetkilere sahip olması
 * - Merkezi yetki yönetimi (tek bir yerden tüm roller kontrol edilir)
 * - Type-safe rol tanımları (String yerine enum)
 * </p>
 *
 * <p><b>NASIL ÇALIŞIR:</b>
 * 1. Her rol bir Set<Permission> tutar
 * 2. getAuthorities() method'u bu permission'ları SimpleGrantedAuthority'ye çevirir
 * 3. Ayrıca "ROLE_" prefix'li rol authority'si de eklenir
 * 4. Spring Security bu authority'leri @PreAuthorize, hasRole(), hasAuthority() için kullanır
 * </p>
 *
 * <p><b>ROL HİYERARŞİSİ:</b>
 * - USER: Hiç permission yok (sadece authenticated user)
 * - MANAGER: Management permission'ları (read, create, update, delete)
 * - ADMIN: Tüm permission'lar (admin + manager permission'ları)
 * </p>
 *
 * <p><b>ÖRNEK KULLANIM:</b>
 * <pre>
 * // Controller'da:
 * {@literal @}PreAuthorize("hasRole('ADMIN')") // Sadece ADMIN rolü
 * {@literal @}PreAuthorize("hasAuthority('admin:read')") // Sadece admin:read yetkisi
 * {@literal @}PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')") // ADMIN veya MANAGER
 * </pre>
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see Permission Detaylı permission tanımları
 * @see User#getAuthorities() User'ın authority'lerini dönen method
 */
@RequiredArgsConstructor // Lombok: final field'lar için constructor oluşturur
public enum Role {

  /**
   * USER Rolü - Standart Kullanıcı
   *
   * <p><b>YETKİLER:</b> Hiç permission yok (boş set)</p>
   *
   * <p><b>ERİŞEBİLECEĞİ ENDPOINT'LER:</b>
   * - /api/v1/demo-controller (authenticated user için açık)
   * - /api/v1/books (GET/POST - authenticated user için açık)
   * </p>
   *
   * <p><b>KULLANIM ALANI:</b> Normal kullanıcılar için, özel yetki gerektirmeyen işlemler</p>
   */
  USER(Collections.emptySet()), // Boş permission set'i

  /**
   * ADMIN Rolü - Sistem Yöneticisi
   *
   * <p><b>YETKİLER:</b> Tüm admin ve manager permission'ları</p>
   *
   * <p><b>PERMISSION'LAR:</b>
   * - ADMIN_READ, ADMIN_CREATE, ADMIN_UPDATE, ADMIN_DELETE
   * - MANAGER_READ, MANAGER_CREATE, MANAGER_UPDATE, MANAGER_DELETE
   * </p>
   *
   * <p><b>ERİŞEBİLECEĞİ ENDPOINT'LER:</b>
   * - /api/v1/admin/** (tüm HTTP methodları)
   * - /api/v1/management/** (tüm HTTP methodları)
   * - Diğer tüm authenticated endpoint'ler
   * </p>
   *
   * <p><b>KULLANIM ALANI:</b> Sistem yöneticileri, full access</p>
   */
  ADMIN(Set.of(ADMIN_READ,      // admin:read
      ADMIN_UPDATE,    // admin:update
      ADMIN_DELETE,    // admin:delete
      ADMIN_CREATE,    // admin:create
      MANAGER_READ,    // management:read
      MANAGER_UPDATE,  // management:update
      MANAGER_DELETE,  // management:delete
      MANAGER_CREATE   // management:create
  )),

  /**
   * MANAGER Rolü - Yönetici
   *
   * <p><b>YETKİLER:</b> Sadece management permission'ları</p>
   *
   * <p><b>PERMISSION'LAR:</b>
   * - MANAGER_READ, MANAGER_CREATE, MANAGER_UPDATE, MANAGER_DELETE
   * </p>
   *
   * <p><b>ERİŞEBİLECEĞİ ENDPOINT'LER:</b>
   * - /api/v1/management/** (tüm HTTP methodları)
   * - Diğer authenticated endpoint'ler
   * </p>
   *
   * <p><b>ERİŞEMEYECEĞİ ENDPOINT'LER:</b>
   * - /api/v1/admin/** (sadece ADMIN rolü için)
   * </p>
   *
   * <p><b>KULLANIM ALANI:</b> Orta seviye yöneticiler, sınırlı admin yetkisi</p>
   */
  MANAGER(Set.of(MANAGER_READ,    // management:read
      MANAGER_UPDATE,  // management:update
      MANAGER_DELETE,  // management:delete
      MANAGER_CREATE   // management:create
  ));

  /**
   * Rol'e ait permission'lar
   *
   * <p>Her rol constructor'da aldığı permission set'ini tutar.
   * Lombok @Getter ile getter method otomatik oluşturulur.</p>
   */
  @Getter
  private final Set<Permission> permissions;

  /**
   * Rol'ün tüm authority'lerini döner (permission'lar + rol authority'si)
   *
   * <p><b>NE:</b> Spring Security'nin kullanacağı GrantedAuthority listesini oluşturur.</p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. Permission set'inden her bir permission alınır
   * 2. Her permission'ın String değeri (örn: "admin:read") SimpleGrantedAuthority'ye çevrilir
   * 3. Stream API ile tüm permission'lar List'e toplanır
   * 4. Son olarak "ROLE_" prefix'li rol authority'si eklenir (örn: "ROLE_ADMIN")
   * 5. Toplam authority listesi döner
   * </p>
   *
   * <p><b>ÖRNEK ÇIKTI (ADMIN için):</b>
   * <pre>
   * [
   *   SimpleGrantedAuthority("admin:read"),
   *   SimpleGrantedAuthority("admin:create"),
   *   SimpleGrantedAuthority("admin:update"),
   *   SimpleGrantedAuthority("admin:delete"),
   *   SimpleGrantedAuthority("management:read"),
   *   SimpleGrantedAuthority("management:create"),
   *   SimpleGrantedAuthority("management:update"),
   *   SimpleGrantedAuthority("management:delete"),
   *   SimpleGrantedAuthority("ROLE_ADMIN")
   * ]
   * </pre>
   * </p>
   *
   * <p><b>NEDEN "ROLE_" PREFIX:</b>
   * Spring Security'de hasRole("ADMIN") kullanıldığında otomatik olarak "ROLE_ADMIN" arar.
   * Bu yüzden manuel olarak "ROLE_" prefix'i ekliyoruz.</p>
   *
   * <p><b>FARK:</b>
   * - hasRole("ADMIN") -> "ROLE_ADMIN" authority'sini arar
   * - hasAuthority("ROLE_ADMIN") -> "ROLE_ADMIN" authority'sini arar
   * - hasAuthority("admin:read") -> "admin:read" authority'sini arar
   * </p>
   *
   * @return Rol'ün tüm authority'leri (permission'lar + rol)
   * @see SimpleGrantedAuthority Spring Security'nin authority implementasyonu
   * @see Permission#getPermission() Permission'ın String değerini döner
   */
  public List<SimpleGrantedAuthority> getAuthorities() {
    // 1. Permission set'inden stream oluştur
    var authorities = getPermissions().stream()
        // 2. Her permission'ı SimpleGrantedAuthority'ye çevir
        .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
        // 3. List'e topla
        .collect(Collectors.toList());

    // 4. "ROLE_" prefix'li rol authority'sini ekle (örn: "ROLE_ADMIN")
    authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));

    // 5. Tüm authority'leri döner
    return authorities;
  }
}