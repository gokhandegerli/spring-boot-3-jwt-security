package com.degerli.security.user;

import com.degerli.security.token.Token;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * User Entity - Kullanıcı Domain Modeli
 *
 * <p><b>NE:</b> Sistemdeki kullanıcıları temsil eden JPA entity sınıfı.
 * Spring Security'nin UserDetails interface'ini implement ederek authentication
 * ve authorization işlemlerinde kullanılır.</p>
 *
 * <p><b>NEDEN:</b>
 * - Spring Security ile entegrasyon için UserDetails gerekli
 * - Kullanıcı bilgilerini veritabanında persist etmek için JPA entity
 * - Role-based authorization için rol bilgisi tutar
 * - Token yönetimi için user-token ilişkisi kurar
 * </p>
 *
 * <p><b>NASIL:</b>
 * - JPA @Entity olarak işaretlenmiş, veritabanında "_user" tablosuna map olur
 * - UserDetails implement ederek Spring Security ile uyumlu hale gelir
 * - Lombok annotations ile boilerplate kod azaltılır
 * - Builder pattern ile nesne oluşturma kolaylaştırılır
 * - OneToMany ilişki ile kullanıcının tüm token'larını takip eder
 * </p>
 *
 * <p><b>ÖNEMLİ NOTLAR:</b>
 * - PostgreSQL'de "user" reserved keyword olduğu için tablo adı "_user"
 * - Email alanı username olarak kullanılıyor (getUsername() -> email döner)
 * - Tüm account durumları (expired, locked, enabled) default true
 * - Password BCrypt ile hash'lenmiş olarak saklanır
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see UserDetails Spring Security'nin user bilgilerini sağlayan interface
 * @see Role Kullanıcı rollerini ve yetkilerini tanımlayan enum
 * @see Token Kullanıcıya ait JWT token'ları tutan entity
 */
@Data // Lombok: getter, setter, toString, equals, hashCode otomatik oluşturur
@Builder // Lombok: Builder pattern implementasyonu sağlar
@NoArgsConstructor // Lombok: Parametresiz constructor (JPA için gerekli)
@AllArgsConstructor // Lombok: Tüm field'ları alan constructor (Builder için gerekli)
@Entity // JPA: Bu sınıfın bir entity olduğunu belirtir
@Table(name = "_user") // PostgreSQL'de "user" reserved keyword olduğu için "_user" kullanıyoruz
public class User implements UserDetails {

  /**
   * Kullanıcının benzersiz kimlik numarası (Primary Key)
   *
   * <p>Veritabanı tarafından otomatik generate edilir (AUTO_INCREMENT)</p>
   */
  @Id // JPA: Primary key field
  @GeneratedValue // JPA: Otomatik ID generation (default strategy: AUTO)
  private Integer id;

  /**
   * Kullanıcının adı
   *
   * <p>Kayıt sırasında RegisterRequest'ten alınır</p>
   */
  private String firstname;

  /**
   * Kullanıcının soyadı
   *
   * <p>Kayıt sırasında RegisterRequest'ten alınır</p>
   */
  private String lastname;

  /**
   * Kullanıcının email adresi
   *
   * <p><b>ÖNEMLİ:</b> Bu alan aynı zamanda username olarak kullanılır.
   * Spring Security authentication işlemlerinde email ile login yapılır.</p>
   *
   * <p><b>TODO:</b> Unique constraint eklenmeli (@Column(unique = true))</p>
   */
  private String email;

  /**
   * Kullanıcının şifresi (BCrypt hash'lenmiş)
   *
   * <p><b>GÜVENLİK:</b> Plain text olarak asla saklanmaz,
   * AuthenticationService'de BCryptPasswordEncoder ile hash'lenir.</p>
   *
   * <p><b>TODO:</b> @JsonIgnore eklenmeli (JSON serialization'da gizlenmeli)</p>
   */
  private String password;

  /**
   * Kullanıcının rolü (ADMIN, MANAGER, USER)
   *
   * <p>Enum olarak saklanır, veritabanında String olarak persist edilir.
   * Her rol farklı permission'lara sahiptir.</p>
   *
   * @see Role Rol tanımları ve permission mapping'leri
   */
  @Enumerated(EnumType.STRING) // Enum'u String olarak veritabanına kaydet (ordinal yerine)
  private Role role;

  /**
   * Kullanıcıya ait tüm JWT token'lar
   *
   * <p><b>İLİŞKİ:</b> One-to-Many (Bir kullanıcının birden fazla token'ı olabilir)
   * - mappedBy: Token entity'sindeki "user" field'ı bu ilişkiyi yönetir
   * - Cascade yok: Token silindiğinde user silinmez
   * - Lazy loading: Token'lar sadece gerektiğinde yüklenir
   * </p>
   *
   * <p><b>KULLANIM:</b> Logout işleminde kullanıcının tüm aktif token'larını
   * revoke etmek için kullanılır.</p>
   */
  @OneToMany(mappedBy = "user") // Token entity'sindeki "user" field'ı owner
  private List<Token> tokens;

  /**
   * Kullanıcının yetkilerini (authorities) döner
   *
   * <p><b>NE:</b> Spring Security'nin yetkilendirme mekanizması için gerekli method.
   * Kullanıcının rolüne göre sahip olduğu tüm permission'ları döner.</p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. User'ın role field'ından rol alınır (örn: ADMIN)
   * 2. Role.getAuthorities() çağrılır
   * 3. Rol'e ait tüm permission'lar SimpleGrantedAuthority olarak döner
   * 4. Spring Security bu authority'leri @PreAuthorize, @Secured vb. için kullanır
   * </p>
   *
   * <p><b>ÖRNEK:</b>
   * ADMIN rolü için dönen authorities:
   * - ROLE_ADMIN
   * - ADMIN_READ
   * - ADMIN_CREATE
   * - ADMIN_UPDATE
   * - ADMIN_DELETE
   * - MANAGER_READ
   * - MANAGER_CREATE
   * - MANAGER_UPDATE
   * - MANAGER_DELETE
   * </p>
   *
   * @return Kullanıcının tüm yetkileri (GrantedAuthority collection)
   * @see Role#getAuthorities() Rol bazlı yetki listesi
   */
  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return role.getAuthorities(); // Role enum'undan authority'leri al
  }

  /**
   * Kullanıcının şifresini döner
   *
   * <p><b>NE:</b> Spring Security authentication sırasında şifre kontrolü için kullanılır.</p>
   *
   * <p><b>NASIL:</b> AuthenticationManager bu method'u çağırır ve
   * PasswordEncoder ile girilen şifreyi karşılaştırır.</p>
   *
   * @return BCrypt hash'lenmiş şifre
   */
  @Override
  public String getPassword() {
    return password; // BCrypt hash'lenmiş şifre
  }

  /**
   * Kullanıcının username'ini döner (email kullanılıyor)
   *
   * <p><b>ÖNEMLİ:</b> Bu projede username olarak email kullanılıyor.
   * Login işleminde email + password ile authentication yapılır.</p>
   *
   * <p><b>ALTERNATIF:</b> Ayrı bir username field'ı da eklenebilir.</p>
   *
   * @return Kullanıcının email adresi (username olarak)
   */
  @Override
  public String getUsername() {
    return email; // Email'i username olarak kullan
  }

  /**
   * Hesabın süresi dolmuş mu kontrolü
   *
   * <p><b>NE:</b> Hesap expiration kontrolü için kullanılır.</p>
   *
   * <p><b>MEVCUT DURUM:</b> Her zaman true döner (hesap süresi dolmaz).
   *
   * <p><b>TODO:</b> Eğer hesap expiration özelliği eklenecekse:
   * - User entity'ye "accountExpiryDate" field'ı ekle
   * - Bu method'da tarih kontrolü yap
   * </p>
   *
   * @return true (hesap süresi dolmamış)
   */
  @Override
  public boolean isAccountNonExpired() {
    return true; // Hesap expiration özelliği yok, her zaman true
  }

  /**
   * Hesap kilitli mi kontrolü
   *
   * <p><b>NE:</b> Hesap kilitleme kontrolü için kullanılır.</p>
   *
   * <p><b>MEVCUT DURUM:</b> Her zaman true döner (hesap kilitli değil).
   *
   * <p><b>TODO:</b> Brute force koruması için:
   * - User entity'ye "accountLocked" boolean field'ı ekle
   * - Başarısız login denemelerini say
   * - 5 başarısız denemeden sonra hesabı kilitle
   * </p>
   *
   * @return true (hesap kilitli değil)
   */
  @Override
  public boolean isAccountNonLocked() {
    return true; // Hesap kilitleme özelliği yok, her zaman true
  }

  /**
   * Şifrenin süresi dolmuş mu kontrolü
   *
   * <p><b>NE:</b> Şifre expiration kontrolü için kullanılır.</p>
   *
   * <p><b>MEVCUT DURUM:</b> Her zaman true döner (şifre süresi dolmaz).
   *
   * <p><b>TODO:</b> Şifre yenileme politikası için:
   * - User entity'ye "passwordChangedDate" field'ı ekle
   * - 90 gün sonra şifre değişikliği zorunlu kıl
   * </p>
   *
   * @return true (şifre süresi dolmamış)
   */
  @Override
  public boolean isCredentialsNonExpired() {
    return true; // Şifre expiration özelliği yok, her zaman true
  }

  /**
   * Hesap aktif mi kontrolü
   *
   * <p><b>NE:</b> Hesap aktivasyon kontrolü için kullanılır.</p>
   *
   * <p><b>MEVCUT DURUM:</b> Her zaman true döner (hesap aktif).
   *
   * <p><b>TODO:</b> Email verification için:
   * - User entity'ye "enabled" boolean field'ı ekle
   * - Kayıt sonrası email doğrulama linki gönder
   * - Email doğrulanınca enabled = true yap
   * </p>
   *
   * @return true (hesap aktif)
   */
  @Override
  public boolean isEnabled() {
    return true; // Email verification yok, her zaman aktif
  }
}