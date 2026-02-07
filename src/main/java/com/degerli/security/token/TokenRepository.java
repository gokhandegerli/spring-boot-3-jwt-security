package com.degerli.security.token;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

/**
 * TokenRepository - JWT Token Veritabanı Erişim Katmanı
 *
 * <p><b>NE:</b> Token entity'si için veritabanı işlemlerini sağlayan Spring Data JPA
 * repository.
 * Custom JPQL query'leri ile kullanıcıya ait geçerli token'ları bulur.</p>
 *
 * <p><b>NEDEN:</b>
 * - Token'ları veritabanında saklamak (stateful JWT)
 * - Kullanıcının tüm geçerli token'larını bulmak (logout için)
 * - Token validation sırasında token'ın DB'de olup olmadığını kontrol etmek
 * - Revoke edilmiş token'ları filtrelemek
 * </p>
 *
 * <p><b>NASIL ÇALIŞIR:</b>
 * 1. Login/Register sırasında token DB'ye kaydedilir
 * 2. Her request'te JwtAuthenticationFilter token'ı DB'den kontrol eder
 * 3. Logout sırasında kullanıcının tüm token'ları revoke edilir
 * 4. Refresh token sırasında eski token'lar revoke edilir
 * </p>
 *
 * <p><b>MEVCUT METHODLAR:</b>
 * - findAllValidTokenByUser(Integer id): Kullanıcının geçerli token'larını bulur (custom
 * query)
 * - findByToken(String token): Token string'i ile token bulur (custom method)
 * - save(Token token): Token kaydetme/güncelleme (JpaRepository'den)
 * - saveAll(List&lt;Token&gt; tokens): Birden fazla token kaydetme (JpaRepository'den)
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Token string'i için unique index ekle
 * - Expired token'ları temizleyen scheduled job ekle
 * - Redis cache ile performans iyileştirmesi
 * - Token expiry date field'ı ekle ve query'de kullan
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see Token JWT token entity'si
 * @see JpaRepository Spring Data JPA'nın base repository interface'i
 */
public interface TokenRepository extends JpaRepository<Token, Integer> {

  /**
   * Kullanıcının tüm geçerli (valid) token'larını bulur
   *
   * <p><b>NE:</b> Verilen user ID'ye ait, expired veya revoked olmayan tüm token'ları döner
   * .</p>
   *
   * <p><b>NEDEN:</b>
   * - Logout işleminde kullanıcının tüm aktif token'larını revoke etmek için
   * - Refresh token işleminde eski token'ları iptal etmek için
   * - Aynı anda birden fazla cihazdan login kontrolü için
   * </p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. JPQL query ile Token ve User tabloları join edilir
   * 2. User ID'ye göre filtreleme yapılır
   * 3. expired=false VEYA revoked=false olan token'lar bulunur
   * 4. Sonuç List olarak döner
   * </p>
   *
   * <p><b>JPQL QUERY ANALİZİ:</b>
   * <pre>
   * SELECT t FROM Token t
   * INNER JOIN User u ON t.user.id = u.id  -- Token ve User join
   * WHERE u.id = :id                        -- User ID filtresi
   * AND (t.expired = false OR t.revoked = false)  -- Geçerli token'lar
   * </pre>
   * </p>
   *
   * <p><b>MANTIK HATASI VAR! 🚨</b>
   * Query'de OR kullanılmış ama AND olmalı!
   *
   * <b>MEVCUT DURUM (YANLIŞ):</b>
   * <pre>
   * (t.expired = false OR t.revoked = false)
   * </pre>
   * Bu şu anlama gelir:
   * - expired=true, revoked=false -> GEÇERLİ (YANLIŞ!)
   * - expired=false, revoked=true -> GEÇERLİ (YANLIŞ!)
   * - expired=true, revoked=true -> GEÇERSİZ (DOĞRU)
   *
   * <b>OLMASI GEREKEN (DOĞRU):</b>
   * <pre>
   * (t.expired = false AND t.revoked = false)
   * </pre>
   * Bu şu anlama gelir:
   * - expired=false, revoked=false -> GEÇERLİ (DOĞRU!)
   * - expired=true, revoked=false -> GEÇERSİZ (DOĞRU!)
   * - expired=false, revoked=true -> GEÇERSİZ (DOĞRU!)
   * - expired=true, revoked=true -> GEÇERSİZ (DOĞRU!)
   * </p>
   *
   * <p><b>KULLANIM YERLERİ:</b>
   * - AuthenticationService.revokeAllUserTokens(): Logout işleminde
   * - AuthenticationService.refreshToken(): Refresh sırasında eski token'ları iptal etmek için
   * </p>
   *
   * <p><b>PERFORMANS:</b>
   * - INNER JOIN kullanılıyor (iyi)
   * - user_id için index var (foreign key otomatik index)
   * - expired ve revoked için composite index eklenebilir
   * </p>
   *
   * <p><b>TODO:</b>
   * Query'yi düzelt: OR yerine AND kullan!
   * <pre>
   * {@literal @}Query(value = """
   *     select t from Token t inner join User u
   *     on t.user.id = u.id
   *     where u.id = :id and (t.expired = false and t.revoked = false)
   * """)
   * </pre>
   * </p>
   *
   * @param id Kullanıcının ID'si
   * @return Kullanıcının geçerli token'larının listesi (boş liste dönebilir)
   * @see com.degerli.security.auth.AuthenticationService#revokeAllUserTokens(User) Bu
   * method'u kullanan yer
   */
  @Query(value = """
      select t from Token t inner join User u\s
      on t.user.id = u.id\s
      where u.id = :id and (t.expired = false or t.revoked = false)\s
      """)
  List<Token> findAllValidTokenByUser(Integer id);

  /**
   * Token string'i ile token bulur
   *
   * <p><b>NE:</b> Verilen JWT token string'ine sahip Token entity'sini bulur.</p>
   *
   * <p><b>NEDEN:</b>
   * - JwtAuthenticationFilter'da token validation için
   * - Token'ın DB'de kayıtlı olup olmadığını kontrol etmek için
   * - Token'ın expired/revoked durumunu kontrol etmek için
   * </p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. Spring Data JPA method ismini parse eder: "findBy" + "Token"
   * 2. Otomatik SQL query oluşturur: "SELECT * FROM token WHERE token = ?"
   * 3. Token bulunursa Optional.of(token), bulunamazsa Optional.empty() döner
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * String jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
   *
   * Optional&lt;Token&gt; tokenOpt = tokenRepository.findByToken(jwtToken);
   *
   * boolean isTokenValid = tokenOpt
   *     .map(t -> !t.isExpired() && !t.isRevoked())
   *     .orElse(false);
   * </pre>
   * </p>
   *
   * <p><b>PERFORMANS:</b>
   * - Token string'i uzun olduğu için (200-500 karakter) index önemli
   * - @Column(unique = true) var ama index eklenebilir
   * - Hash-based index kullanılabilir (PostgreSQL)
   * </p>
   *
   * <p><b>KULLANIM YERLERİ:</b>
   * - JwtAuthenticationFilter.doFilterInternal(): Token validation
   * - LogoutService.logout(): Logout işleminde token'ı bulmak için
   * </p>
   *
   * @param token JWT token string'i (örn: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
   * @return Token bulunursa Optional.of(token), bulunamazsa Optional.empty()
   * @see com.degerli.security.config.JwtAuthenticationFilter#doFilterInternal Token
   * validation yapan yer
   * @see com.degerli.security.config.LogoutService#logout Logout işleminde kullanan yer
   */
  Optional<Token> findByToken(String token);
}