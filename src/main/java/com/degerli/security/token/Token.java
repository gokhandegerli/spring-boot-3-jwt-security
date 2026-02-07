package com.degerli.security.token;

import com.degerli.security.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Token Entity - JWT Token Yönetimi
 *
 * <p><b>NE:</b> Kullanıcılara ait JWT token'ları veritabanında saklayan entity.
 * Token'ın geçerlilik durumunu (expired, revoked) takip eder.</p>
 *
 * <p><b>NEDEN:</b>
 * - Token'ları veritabanında saklamak (stateful JWT)
 * - Logout işleminde token'ı revoke edebilmek
 * - Aynı anda birden fazla cihazdan login kontrolü
 * - Token'ın geçerlilik durumunu kontrol etmek
 * - Güvenlik: Çalınan token'ı manuel olarak iptal edebilmek
 * </p>
 *
 * <p><b>NASIL ÇALIŞIR:</b>
 * 1. Login/Register sırasında JWT oluşturulur
 * 2. Token entity'si oluşturulup veritabanına kaydedilir
 * 3. Her request'te JwtAuthenticationFilter token'ı kontrol eder
 * 4. Token veritabanında var mı, expired/revoked değil mi kontrol edilir
 * 5. Logout sırasında token expired=true, revoked=true yapılır
 * </p>
 *
 * <p><b>STATEFUL vs STATELESS JWT:</b>
 * - Bu proje STATEFUL JWT kullanıyor (token'lar DB'de saklanıyor)
 * - Avantaj: Token'ı manuel olarak iptal edebilme
 * - Dezavantaj: Her request'te DB sorgusu (performans)
 * - Alternatif: Redis cache kullanılabilir
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Token expiry date field'ı ekle (LocalDateTime)
 * - Expired token'ları temizleyen scheduled job ekle
 * - Redis cache ile performans iyileştirmesi
 * - Token refresh mekanizması için ayrı tablo
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see User Token'ın sahibi olan kullanıcı
 * @see TokenType Token tipi (BEARER)
 * @see com.degerli.security.config.JwtAuthenticationFilter Token validation yapan filter
 */
@Data // Lombok: getter, setter, toString, equals, hashCode
@Builder // Lombok: Builder pattern
@NoArgsConstructor // Lombok: Parametresiz constructor (JPA için gerekli)
@AllArgsConstructor // Lombok: Tüm field'ları alan constructor
@Entity // JPA: Bu sınıf bir entity
public class Token {

  /**
   * Token'ın benzersiz kimlik numarası (Primary Key)
   *
   * <p>Veritabanı tarafından otomatik generate edilir</p>
   */
  @Id
  @GeneratedValue
  public Integer id;

  /**
   * JWT token string'i
   *
   * <p><b>FORMAT:</b> "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."</p>
   *
   * <p><b>UNIQUE:</b> Her token benzersiz olmalı (aynı token iki kez kaydedilmemeli)</p>
   *
   * <p><b>BOYUT:</b> JWT token'lar genelde 200-500 karakter arası
   * VARCHAR(1000) veya TEXT kullanılabilir</p>
   *
   * <p><b>TODO:</b> @Column(length = 1000) ekle</p>
   */
  @Column(unique = true) // Unique constraint: Aynı token iki kez kaydedilemez
  public String token;

  /**
   * Token tipi (BEARER)
   *
   * <p><b>MEVCUT DURUM:</b> Sadece BEARER tipi kullanılıyor</p>
   *
   * <p><b>BEARER TOKEN:</b> HTTP Authorization header'ında "Bearer {token}" formatında
   * gönderilir</p>
   *
   * <p><b>GELECEK:</b> Farklı token tipleri eklenebilir (API_KEY, OAUTH2, vb.)</p>
   */
  @Enumerated(EnumType.STRING) // Enum'u String olarak sakla
  public TokenType tokenType = TokenType.BEARER; // Default değer: BEARER

  /**
   * Token iptal edildi mi?
   *
   * <p><b>NE ZAMAN TRUE:</b>
   * - Kullanıcı logout yaptığında
   * - Yeni token oluşturulduğunda eski token'lar revoke edildiğinde
   * - Admin tarafından manuel olarak iptal edildiğinde
   * </p>
   *
   * <p><b>KULLANIM:</b> JwtAuthenticationFilter'da kontrol edilir.
   * Eğer revoked=true ise token geçersiz sayılır.</p>
   */
  public boolean revoked;

  /**
   * Token'ın süresi doldu mu?
   *
   * <p><b>NE ZAMAN TRUE:</b>
   * - Token'ın expiration time'ı geçtiğinde
   * - Logout işleminde (revoked ile birlikte)
   * </p>
   *
   * <p><b>NOT:</b> JWT'nin kendi expiration claim'i var ama
   * veritabanında da tutuyoruz (double check için)</p>
   *
   * <p><b>KULLANIM:</b> JwtAuthenticationFilter'da kontrol edilir.
   * Eğer expired=true ise token geçersiz sayılır.</p>
   */
  public boolean expired;

  /**
   * Token'ın sahibi olan kullanıcı
   *
   * <p><b>İLİŞKİ:</b> Many-to-One (Birden fazla token bir kullanıcıya ait olabilir)</p>
   *
   * <p><b>LAZY LOADING:</b> User bilgisi sadece gerektiğinde yüklenir (performans)</p>
   *
   * <p><b>FOREIGN KEY:</b> user_id kolonu User tablosuna referans verir</p>
   *
   * <p><b>KULLANIM:</b>
   * - Logout işleminde kullanıcının tüm token'larını bulmak için
   * - Token'ın hangi kullanıcıya ait olduğunu bilmek için
   * </p>
   */
  @ManyToOne(fetch = FetchType.LAZY) // Lazy loading: User sadece gerektiğinde yüklenir
  @JoinColumn(name = "user_id") // Foreign key kolonu: user_id
  public User user;
}