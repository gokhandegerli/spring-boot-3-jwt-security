package com.degerli.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

/**
 * JwtService - JWT Token İşlemleri Servisi
 *
 * <p><b>NE:</b> JWT (JSON Web Token) oluşturma, parse etme ve validation işlemlerini yapan
 * servis.
 * JJWT kütüphanesini kullanarak token generation ve verification sağlar.</p>
 *
 * <p><b>NEDEN:</b>
 * - Stateless authentication için JWT kullanmak
 * - Token-based authorization mekanizması
 * - Kullanıcı bilgilerini token içinde taşımak (claims)
 * - Token expiration kontrolü
 * - Refresh token mekanizması
 * </p>
 *
 * <p><b>NASIL ÇALIŞIR:</b>
 * 1. Login/Register sırasında JWT oluşturulur (generateToken)
 * 2. Token HTTP Authorization header'ında client'a gönderilir
 * 3. Her request'te client token'ı gönderir
 * 4. JwtAuthenticationFilter token'ı parse eder ve validate eder
 * 5. Token geçerliyse user authenticated olur
 * </p>
 *
 * <p><b>JWT YAPISI:</b>
 * JWT üç kısımdan oluşur (Base64 encoded):
 * <pre>
 * HEADER.PAYLOAD.SIGNATURE
 *
 * HEADER: {"alg": "HS256", "typ": "JWT"}
 * PAYLOAD: {"sub": "user@mail.com", "iat": 1234567890, "exp": 1234571490}
 * SIGNATURE: HMACSHA256(base64(header) + "." + base64(payload), SECRET_KEY)
 * </pre>
 * </p>
 *
 * <p><b>TOKEN TİPLERİ:</b>
 * - Access Token: Kısa ömürlü (1 gün), API erişimi için
 * - Refresh Token: Uzun ömürlü (7 gün), yeni access token almak için
 * </p>
 *
 * <p><b>GÜVENLİK NOTLARI:</b>
 * - SECRET_KEY application.yml'de saklanıyor (YANLIŞ! Environment variable olmalı)
 * - HS256 algoritması kullanılıyor (deprecated, HS512 kullanılmalı)
 * - Token'lar DB'de saklanıyor (stateful JWT)
 * - HTTPS kullanılmalı (token çalınma riski)
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - SignatureAlgorithm.HS256 -> SignatureAlgorithm.HS512
 * - SECRET_KEY'i environment variable'dan al
 * - Token blacklist mekanizması ekle (Redis)
 * - Token rotation stratejisi ekle
 * - Custom claims ekle (role, permissions)
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see io.jsonwebtoken.Jwts JJWT kütüphanesinin ana sınıfı
 * @see com.degerli.security.config.JwtAuthenticationFilter Token validation yapan filter
 * @see com.degerli.security.auth.AuthenticationService Token generate eden servis
 */
@Service
public class JwtService {

  /**
   * JWT imzalama için kullanılan secret key
   *
   * <p><b>KAYNAK:</b> application.yml -> application.security.jwt.secret-key</p>
   *
   * <p><b>FORMAT:</b> Base64 encoded string (minimum 256 bit / 32 byte)</p>
   *
   * <p><b>GÜVENLİK UYARISI! 🚨</b>
   * - Secret key application.yml'de hardcoded (YANLIŞ!)
   * - Environment variable olarak saklanmalı
   * - Production'da mutlaka değiştirilmeli
   * - Key rotation stratejisi olmalı
   * </p>
   *
   * <p><b>DOĞRU KULLANIM:</b>
   * <pre>
   * # .env dosyası
   * JWT_SECRET_KEY=your-secret-key-here
   *
   * # application.yml
   * application:
   *   security:
   *     jwt:
   *       secret-key: ${JWT_SECRET_KEY}
   * </pre>
   * </p>
   */
  @Value("${application.security.jwt.secret-key}")
  private String secretKey;

  /**
   * Access token'ın geçerlilik süresi (milisaniye)
   *
   * <p><b>KAYNAK:</b> application.yml -> application.security.jwt.expiration</p>
   *
   * <p><b>DEĞER:</b> 86400000 ms = 24 saat = 1 gün</p>
   *
   * <p><b>NEDEN 1 GÜN:</b>
   * - Çok kısa: Kullanıcı deneyimi kötü (sürekli login)
   * - Çok uzun: Güvenlik riski (çalınan token uzun süre geçerli)
   * - 1 gün: Dengeli bir süre
   * </p>
   *
   * <p><b>ALTERNATİFLER:</b>
   * - 15 dakika: Yüksek güvenlik gerektiren sistemler
   * - 1 saat: Orta güvenlik
   * - 1 gün: Düşük güvenlik, iyi UX
   * </p>
   */
  @Value("${application.security.jwt.expiration}")
  private long jwtExpiration;

  /**
   * Refresh token'ın geçerlilik süresi (milisaniye)
   *
   * <p><b>KAYNAK:</b> application.yml -> application.security.jwt.refresh-token.expiration</p>
   *
   * <p><b>DEĞER:</b> 604800000 ms = 7 gün</p>
   *
   * <p><b>NEDEN 7 GÜN:</b>
   * - Access token'dan uzun olmalı (refresh için)
   * - Çok uzun olmamalı (güvenlik riski)
   * - 7 gün: Kullanıcı haftada bir login yapar
   * </p>
   *
   * <p><b>KULLANIM:</b>
   * - Access token expire olduğunda refresh token ile yeni access token alınır
   * - Refresh token da expire olursa kullanıcı tekrar login yapar
   * </p>
   */
  @Value("${application.security.jwt.refresh-token.expiration}")
  private long refreshExpiration;

  /**
   * JWT token'dan username (email) çıkarır
   *
   * <p><b>NE:</b> Token'ın payload kısmındaki "subject" claim'ini döner.
   * Bu projede subject olarak email kullanılıyor.</p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. extractClaim() method'u çağrılır
   * 2. Claims::getSubject method reference ile subject claim alınır
   * 3. Subject (email) String olarak döner
   * </p>
   *
   * <p><b>KULLANIM YERLERİ:</b>
   * - JwtAuthenticationFilter: Token'dan user bilgisi almak için
   * - Token validation: Token'ın hangi user'a ait olduğunu bilmek için
   * </p>
   *
   * <p><b>ÖRNEK:</b>
   * <pre>
   * String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
   * String email = jwtService.extractUsername(token);
   * // email = "admin@mail.com"
   * </pre>
   * </p>
   *
   * @param token JWT token string'i
   * @return Token'daki username (email)
   * @see #extractClaim(String, Function) Generic claim extraction method
   */
  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject); // Subject claim'i al (email)
  }

  /**
   * JWT token'dan belirli bir claim çıkarır (generic method)
   *
   * <p><b>NE:</b> Token'ın payload kısmından istenen claim'i çıkarır.
   * Function parameter ile hangi claim'in alınacağı belirlenir.</p>
   *
   * <p><b>NEDEN GENERIC:</b>
   * - Farklı claim'ler için aynı kodu tekrar yazmamak
   * - Type-safe claim extraction
   * - Functional programming yaklaşımı
   * </p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. extractAllClaims() ile token'daki tüm claim'ler alınır
   * 2. claimsResolver function'ı apply edilir
   * 3. İstenen claim döner
   * </p>
   *
   * <p><b>KULLANIM ÖRNEKLERİ:</b>
   * <pre>
   * // Username (subject) alma
   * String username = extractClaim(token, Claims::getSubject);
   *
   * // Expiration date alma
   * Date expiration = extractClaim(token, Claims::getExpiration);
   *
   * // Issued at date alma
   * Date issuedAt = extractClaim(token, Claims::getIssuedAt);
   *
   * // Custom claim alma
   * String role = extractClaim(token, claims -> claims.get("role", String.class));
   * </pre>
   * </p>
   *
   * @param <T>            Claim'in tipi (String, Date, Integer, vb.)
   * @param token          JWT token string'i
   * @param claimsResolver Claim'i extract eden function (method reference)
   * @return İstenen claim
   * @see #extractAllClaims(String) Tüm claim'leri parse eden method
   */
  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token); // Tüm claim'leri al
    return claimsResolver.apply(claims); // İstenen claim'i extract et
  }

  /**
   * Sadece UserDetails ile JWT token oluşturur (extra claims yok)
   *
   * <p><b>NE:</b> Kullanıcı bilgilerinden JWT token oluşturur.
   * Extra claim eklemeden sadece default claim'lerle token üretir.</p>
   *
   * <p><b>DEFAULT CLAIMS:</b>
   * - subject: UserDetails.getUsername() (email)
   * - issuedAt: Token oluşturulma zamanı
   * - expiration: Token geçerlilik süresi
   * </p>
   *
   * <p><b>KULLANIM YERLERİ:</b>
   * - AuthenticationService.register(): Kayıt sonrası token oluşturma
   * - AuthenticationService.authenticate(): Login sonrası token oluşturma
   * </p>
   *
   * <p><b>ÖRNEK:</b>
   * <pre>
   * UserDetails user = ...; // User entity (UserDetails implement eder)
   * String token = jwtService.generateToken(user);
   * // token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * </pre>
   * </p>
   *
   * @param userDetails Kullanıcı bilgileri (User entity)
   * @return JWT access token
   * @see #generateToken(Map, UserDetails) Extra claims ile token oluşturan method
   */
  public String generateToken(UserDetails userDetails) {
    return generateToken(new HashMap<>(), userDetails); // Boş extra claims ile token oluştur
  }

  /**
   * Extra claims ile JWT token oluşturur
   *
   * <p><b>NE:</b> Kullanıcı bilgileri ve extra claim'lerle JWT token oluşturur.
   * Access token için kullanılır (kısa ömürlü).</p>
   *
   * <p><b>EXTRA CLAIMS:</b>
   * Token'a ekstra bilgiler eklemek için kullanılır:
   * - role: Kullanıcının rolü
   * - permissions: Kullanıcının yetkileri
   * - customData: Özel veriler
   * </p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. buildToken() method'u çağrılır
   * 2. Extra claims, userDetails ve expiration süresi verilir
   * 3. JWT token oluşturulur ve döner
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * Map&lt;String, Object&gt; extraClaims = new HashMap&lt;&gt;();
   * extraClaims.put("role", user.getRole().name());
   * extraClaims.put("userId", user.getId());
   *
   * String token = jwtService.generateToken(extraClaims, user);
   * </pre>
   * </p>
   *
   * <p><b>NOT:</b>
   * Şu anda extra claims kullanılmıyor (boş Map gönderiliyor).
   * Gelecekte role, permissions eklenebilir.
   * </p>
   *
   * @param extraClaims Token'a eklenecek extra claim'ler (role, permissions, vb.)
   * @param userDetails Kullanıcı bilgileri
   * @return JWT access token
   * @see #buildToken(Map, UserDetails, long) Token builder method
   */
  public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
    return buildToken(extraClaims, userDetails, jwtExpiration); // Access token oluştur (1 gün)
  }

  /**
   * Refresh token oluşturur
   *
   * <p><b>NE:</b> Uzun ömürlü refresh token oluşturur.
   * Access token expire olduğunda yeni access token almak için kullanılır.</p>
   *
   * <p><b>REFRESH TOKEN AKIŞI:</b>
   * 1. Login sırasında hem access token hem refresh token oluşturulur
   * 2. Access token expire olduğunda client refresh token gönderir
   * 3. Refresh token geçerliyse yeni access token oluşturulur
   * 4. Refresh token da expire olursa kullanıcı tekrar login yapar
   * </p>
   *
   * <p><b>FARK:</b>
   * - Access Token: 1 gün (jwtExpiration)
   * - Refresh Token: 7 gün (refreshExpiration)
   * </p>
   *
   * <p><b>KULLANIM YERİ:</b>
   * - AuthenticationService.register(): Kayıt sonrası
   * - AuthenticationService.authenticate(): Login sonrası
   * - AuthenticationService.refreshToken(): Refresh işleminde
   * </p>
   *
   * <p><b>ÖRNEK:</b>
   * <pre>
   * UserDetails user = ...;
   * String refreshToken = jwtService.generateRefreshToken(user);
   * // refreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." (7 gün geçerli)
   * </pre>
   * </p>
   *
   * @param userDetails Kullanıcı bilgileri
   * @return JWT refresh token (7 gün geçerli)
   * @see #buildToken(Map, UserDetails, long) Token builder method
   */
  public String generateRefreshToken(UserDetails userDetails) {
    return buildToken(new HashMap<>(), userDetails,
        refreshExpiration); // Refresh token oluştur (7 gün)
  }

  /**
   * JWT token oluşturur (core method)
   *
   * <p><b>NE:</b> Verilen parametrelerle JWT token oluşturan core method.
   * Hem access token hem refresh token bu method ile oluşturulur.</p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. Jwts.builder() ile builder oluşturulur
   * 2. Extra claims eklenir (setClaims)
   * 3. Subject (username/email) eklenir (setSubject)
   * 4. Issued at (oluşturulma zamanı) eklenir (setIssuedAt)
   * 5. Expiration (geçerlilik süresi) eklenir (setExpiration)
   * 6. Secret key ile imzalanır (signWith)
   * 7. Token string'e çevrilir (compact)
   * </p>
   *
   * <p><b>TOKEN YAPISI:</b>
   * <pre>
   * {
   *   "sub": "admin@mail.com",           // Subject (username)
   *   "iat": 1234567890,                 // Issued at (oluşturulma zamanı)
   *   "exp": 1234654290,                 // Expiration (geçerlilik süresi)
   *   "role": "ADMIN",                   // Extra claim (opsiyonel)
   *   "permissions": ["admin:read", ...] // Extra claim (opsiyonel)
   * }
   * </pre>
   * </p>
   *
   * <p><b>İMZALAMA:</b>
   * - Algoritma: HS256 (HMAC with SHA-256)
   * - Key: Secret key (Base64 decoded)
   * - Signature: HMACSHA256(header + payload, secret)
   * </p>
   *
   * <p><b>GÜVENLİK UYARISI! 🚨</b>
   * SignatureAlgorithm.HS256 deprecated!
   * HS512 kullanılmalı (daha güvenli):
   * <pre>
   * .signWith(getSignInKey(), SignatureAlgorithm.HS512)
   * </pre>
   * </p>
   *
   * @param extraClaims Token'a eklenecek extra claim'ler
   * @param userDetails Kullanıcı bilgileri
   * @param expiration  Token geçerlilik süresi (milisaniye)
   * @return JWT token string'i
   * @see #getSignInKey() Secret key'i decode eden method
   */
  private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails,
      long expiration) {
    return Jwts.builder() // JWT builder oluştur
        .setClaims(extraClaims) // Extra claim'leri ekle (role, permissions, vb.)
        .setSubject(userDetails.getUsername()) // Subject: username (email)
        .setIssuedAt(new Date(System.currentTimeMillis())) // Issued at: şu an
        .setExpiration(
            new Date(System.currentTimeMillis() + expiration)) // Expiration: şu an + süre
        .signWith(getSignInKey(),
            SignatureAlgorithm.HS256) // Secret key ile imzala (HS256 - DEPRECATED!)
        .compact(); // Token string'e çevir
  }

  /**
   * JWT token'ın geçerli olup olmadığını kontrol eder
   *
   * <p><b>NE:</b> Token'ın hem username'inin doğru olduğunu hem de expire olmadığını
   * kontrol eder.</p>
   *
   * <p><b>VALIDATION ADIMLARI:</b>
   * 1. Token'dan username (email) çıkarılır
   * 2. Token'daki username ile UserDetails'daki username karşılaştırılır
   * 3. Token'ın expire olup olmadığı kontrol edilir
   * 4. Her iki kontrol de geçerse true döner
   * </p>
   *
   * <p><b>KULLANIM YERİ:</b>
   * - JwtAuthenticationFilter.doFilterInternal(): Her request'te token validation
   * </p>
   *
   * <p><b>ÖRNEK:</b>
   * <pre>
   * String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
   * UserDetails user = userDetailsService.loadUserByUsername("admin@mail.com");
   *
   * boolean isValid = jwtService.isTokenValid(token, user);
   * // isValid = true (token geçerli)
   * </pre>
   * </p>
   *
   * <p><b>NEDEN İKİ KONTROL:</b>
   * - Username kontrolü: Token'ın doğru user'a ait olduğunu garanti eder
   * - Expiration kontrolü: Token'ın süresi dolmadığını garanti eder
   * </p>
   *
   * @param token       JWT token string'i
   * @param userDetails Kullanıcı bilgileri (DB'den alınan)
   * @return Token geçerliyse true, değilse false
   * @see #extractUsername(String) Token'dan username çıkarır
   * @see #isTokenExpired(String) Token expire kontrolü
   */
  public boolean isTokenValid(String token, UserDetails userDetails) {
    final String username = extractUsername(token); // Token'dan username al
    return (username.equals(userDetails.getUsername())) && !isTokenExpired(
        token); // Username eşleşiyor mu ve expire olmamış mı?
  }

  /**
   * Token'ın süresi dolmuş mu kontrol eder
   *
   * <p><b>NE:</b> Token'ın expiration claim'ini kontrol eder.
   * Expiration date geçmişse true döner.</p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. extractExpiration() ile token'dan expiration date alınır
   * 2. Expiration date ile şu anki zaman karşılaştırılır
   * 3. Expiration < now ise true (expire olmuş)
   * </p>
   *
   * <p><b>ÖRNEK:</b>
   * <pre>
   * // Token 1 gün önce oluşturulmuş, 1 gün geçerli
   * String token = "...";
   * boolean isExpired = jwtService.isTokenExpired(token);
   * // isExpired = false (henüz expire olmamış)
   *
   * // Token 2 gün önce oluşturulmuş, 1 gün geçerli
   * String oldToken = "...";
   * boolean isExpired2 = jwtService.isTokenExpired(oldToken);
   * // isExpired2 = true (expire olmuş)
   * </pre>
   * </p>
   *
   * @param token JWT token string'i
   * @return Token expire olduysa true, değilse false
   * @see #extractExpiration(String) Token'dan expiration date çıkarır
   */
  private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date()); // Expiration date geçmiş mi?
  }

  /**
   * Token'dan expiration date çıkarır
   *
   * <p><b>NE:</b> Token'ın payload kısmındaki "exp" claim'ini döner.</p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. extractClaim() method'u çağrılır
   * 2. Claims::getExpiration method reference ile exp claim alınır
   * 3. Expiration date döner
   * </p>
   *
   * <p><b>ÖRNEK:</b>
   * <pre>
   * String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
   * Date expiration = jwtService.extractExpiration(token);
   * // expiration = 2024-01-02 12:00:00 (1 gün sonra)
   * </pre>
   * </p>
   *
   * @param token JWT token string'i
   * @return Token'ın expiration date'i
   * @see #extractClaim(String, Function) Generic claim extraction
   */
  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration); // Expiration claim'i al
  }

  /**
   * Token'dan tüm claim'leri çıkarır (parse eder)
   *
   * <p><b>NE:</b> JWT token'ı parse ederek payload kısmındaki tüm claim'leri döner.</p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. Jwts.parserBuilder() ile parser oluşturulur
   * 2. Secret key ile imza doğrulaması yapılır (setSigningKey)
   * 3. Parser build edilir
   * 4. Token parse edilir (parseClaimsJws)
   * 5. Payload (claims) döner
   * </p>
   *
   * <p><b>İMZA DOĞRULAMA:</b>
   * - Token'ın signature kısmı secret key ile doğrulanır
   * - Eğer token manipüle edildiyse SignatureException fırlatılır
   * - Eğer token expire olduysa ExpiredJwtException fırlatılır
   * </p>
   *
   * <p><b>EXCEPTION'LAR:</b>
   * - SignatureException: Token imzası geçersiz (manipüle edilmiş)
   * - ExpiredJwtException: Token süresi dolmuş
   * - MalformedJwtException: Token formatı hatalı
   * - UnsupportedJwtException: Token tipi desteklenmiyor
   * </p>
   *
   * <p><b>ÖRNEK CLAIMS:</b>
   * <pre>
   * {
   *   "sub": "admin@mail.com",
   *   "iat": 1234567890,
   *   "exp": 1234654290,
   *   "role": "ADMIN"
   * }
   * </pre>
   * </p>
   *
   * <p><b>TODO:</b>
   * Exception handling ekle (try-catch ile custom exception fırlat)
   * </p>
   *
   * @param token JWT token string'i
   * @return Token'daki tüm claim'ler
   * @throws io.jsonwebtoken.SignatureException  Token imzası geçersiz
   * @throws io.jsonwebtoken.ExpiredJwtException Token süresi dolmuş
   * @see #getSignInKey() Secret key'i decode eden method
   */
  private Claims extractAllClaims(String token) {
    return Jwts.parserBuilder() // JWT parser builder oluştur
        .setSigningKey(getSignInKey()) // Secret key ile imza doğrulama
        .build() // Parser'ı build et
        .parseClaimsJws(token) // Token'ı parse et (imza doğrulama yapılır)
        .getBody(); // Payload (claims) döner
  }

  /**
   * Secret key'i decode eder ve Key objesine çevirir
   *
   * <p><b>NE:</b> Base64 encoded secret key'i decode ederek HMAC-SHA key objesine çevirir.</p>
   *
   * <p><b>NEDEN:</b>
   * - JJWT kütüphanesi Key objesi bekler (String değil)
   * - Secret key Base64 encoded olarak saklanıyor
   * - HMAC-SHA algoritması için uygun key formatı gerekli
   * </p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * 1. Secret key Base64 decode edilir (Decoders.BASE64.decode)
   * 2. Byte array'e çevrilir
   * 3. HMAC-SHA key objesine çevrilir (Keys.hmacShaKeyFor)
   * 4. Key objesi döner
   * </p>
   *
   * <p><b>KEY BOYUTU:</b>
   * - HS256: Minimum 256 bit (32 byte)
   * - HS512: Minimum 512 bit (64 byte)
   * - Daha uzun key = daha güvenli
   * </p>
   *
   * <p><b>ÖRNEK:</b>
   * <pre>
   * // application.yml
   * secret-key: "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970"
   *
   * // Decode edilmiş key
   * byte[] keyBytes = [64, 78, 99, 82, 102, 85, ...] // 32 byte
   * Key key = Keys.hmacShaKeyFor(keyBytes);
   * </pre>
   * </p>
   *
   * @return HMAC-SHA key objesi
   * @see io.jsonwebtoken.security.Keys JJWT'nin key utility sınıfı
   */
  private Key getSignInKey() {
    byte[] keyBytes = Decoders.BASE64.decode(secretKey); // Base64 decode
    return Keys.hmacShaKeyFor(keyBytes); // HMAC-SHA key oluştur
  }
}