package com.degerli.security.user;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * UserRepository - Kullanıcı Veritabanı Erişim Katmanı
 *
 * <p><b>NE:</b> User entity'si için veritabanı işlemlerini sağlayan Spring Data JPA
 * repository interface'i.
 * JpaRepository'den extend ederek CRUD operasyonlarını otomatik kazanır.</p>
 *
 * <p><b>NEDEN:</b>
 * - Veritabanı işlemlerini soyutlamak (abstraction)
 * - Boilerplate kod yazmaktan kurtulmak (Spring Data JPA otomatik implement eder)
 * - Email ile kullanıcı arama özelliği (authentication için gerekli)
 * - Transaction yönetimi (Spring otomatik halleder)
 * </p>
 *
 * <p><b>NASIL ÇALIŞIR:</b>
 * 1. Spring Data JPA bu interface'i runtime'da implement eder (proxy pattern)
 * 2. Method isimlendirme convention'ına göre SQL query'leri otomatik oluşturulur
 * 3. findByEmail -> "SELECT * FROM _user WHERE email = ?" query'sine çevrilir
 * 4. JpaRepository'den gelen tüm CRUD methodları kullanılabilir
 * </p>
 *
 * <p><b>MEVCUT METHODLAR:</b>
 * - findByEmail(String email): Email ile kullanıcı arama (custom method)
 * - save(User user): Kullanıcı kaydetme/güncelleme (JpaRepository'den)
 * - findById(Integer id): ID ile kullanıcı bulma (JpaRepository'den)
 * - findAll(): Tüm kullanıcıları listeleme (JpaRepository'den)
 * - delete(User user): Kullanıcı silme (JpaRepository'den)
 * - count(): Toplam kullanıcı sayısı (JpaRepository'den)
 * </p>
 *
 * <p><b>KULLANIM ÖRNEKLERİ:</b>
 * <pre>
 * // Email ile kullanıcı bulma (authentication için)
 * Optional&lt;User&gt; user = userRepository.findByEmail("admin@mail.com");
 *
 * // Yeni kullanıcı kaydetme
 * User newUser = User.builder().email("test@mail.com").build();
 * userRepository.save(newUser);
 *
 * // Kullanıcı güncelleme
 * user.ifPresent(u -> {
 *     u.setPassword(newPassword);
 *     userRepository.save(u); // save() hem insert hem update yapar
 * });
 * </pre>
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Email için unique index ekle (performans)
 * - existsByEmail(String email) method'u ekle (email kontrolü için)
 * - Custom query'ler için @Query annotation kullan
 * - Pagination desteği ekle (findAll(Pageable pageable))
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see User Kullanıcı entity'si
 * @see JpaRepository Spring Data JPA'nın base repository interface'i
 * @see org.springframework.data.jpa.repository.config.EnableJpaRepositories Repository'leri
 * aktif eden annotation
 */
public interface UserRepository extends JpaRepository<User, Integer> {

  /**
   * Email adresine göre kullanıcı bulur
   *
   * <p><b>NE:</b> Verilen email adresine sahip kullanıcıyı veritabanından arar.</p>
   *
   * <p><b>NEDEN:</b>
   * - Authentication işleminde kullanıcı doğrulaması için
   * - Email ile login yapılıyor (username yerine)
   * - UserDetailsService'de loadUserByUsername() için gerekli
   * </p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. Spring Data JPA method ismini parse eder: "findBy" + "Email"
   * 2. Otomatik SQL query oluşturur: "SELECT * FROM _user WHERE email = ?"
   * 3. Query'yi execute eder ve sonucu Optional'a wrap'ler
   * 4. Kullanıcı bulunursa Optional.of(user), bulunamazsa Optional.empty() döner
   * </p>
   *
   * <p><b>OPTIONAL KULLANIMI:</b>
   * Optional kullanmak null check'lerden kurtarır ve daha güvenli kod sağlar.
   * <pre>
   * // Kötü yöntem (null check):
   * User user = userRepository.findByEmail(email);
   * if (user != null) { ... }
   *
   * // İyi yöntem (Optional):
   * userRepository.findByEmail(email)
   *     .ifPresent(user -> { ... });
   *
   * // Exception fırlatma:
   * User user = userRepository.findByEmail(email)
   *     .orElseThrow(() -> new UsernameNotFoundException("User not found"));
   * </pre>
   * </p>
   *
   * <p><b>PERFORMANS:</b>
   * - Email alanına index eklenirse çok daha hızlı çalışır
   * - Şu anki hali: Full table scan (yavaş)
   * - Index ile: O(log n) complexity (hızlı)
   * </p>
   *
   * <p><b>KULLANIM YERLERİ:</b>
   * - ApplicationConfig.userDetailsService(): Authentication için
   * - AuthenticationService.register(): Email duplicate kontrolü için (TODO)
   * </p>
   *
   * @param email Aranacak email adresi (örn: "admin@mail.com")
   * @return Kullanıcı bulunursa Optional.of(user), bulunamazsa Optional.empty()
   * @see Optional Java 8'in null-safe container'ı
   * @see com.degerli.security.config.ApplicationConfig#userDetailsService() Bu method'u
   * kullanan yer
   */
  Optional<User> findByEmail(String email);
}