package com.degerli.security.config;

import com.degerli.security.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

/**
 * LogoutService - Çıkış İşlemi Servisi
 *
 * <p><b>NE:</b> Kullanıcı logout işlemini yöneten servis.
 * Spring Security'nin LogoutHandler interface'ini implement eder.</p>
 *
 * <p><b>NEDEN:</b>
 * - Logout işleminde token'ı revoke etmek (geçersiz kılmak)
 * - Stateful JWT için token'ı DB'de expired/revoked olarak işaretlemek
 * - SecurityContext'i temizlemek (kullanıcı oturumunu sonlandırmak)
 * - Güvenlik: Çıkış yapıldığında token'ın artık kullanılamaması
 * - <b>⚠️ KRİTİK:</b> Sadece gönderilen token'ı değil, user'ın TÜM token'larını revoke etmek!
 * </p>
 *
 * <p><b>NASIL ÇALIŞIR:</b>
 * 1. Client logout endpoint'ine request gönderir (Authorization header'ında token)
 * 2. LogoutService.logout() method'u çağrılır
 * 3. Authorization header'ından token çıkarılır
 * 4. Token DB'den bulunur
 * 5. Token'ın sahibi olan user'ın TÜM token'ları bulunur (ACCESS + REFRESH)
 * 6. TÜM token'lar expired ve revoked olarak işaretlenir
 * 7. SecurityContext temizlenir (kullanıcı oturumu sonlandırılır)
 * </p>
 *
 * <p><b>LOGOUT AKIŞI:</b>
 * <pre>
 * POST /api/v1/auth/logout
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *
 * -> LogoutService.logout() çağrılır
 * -> Token DB'den bulunur
 * -> User'ın TÜM token'ları bulunur (findAllValidTokenByUser)
 * -> TÜM token'lar: expired = true, revoked = true
 * -> Token'lar DB'ye kaydedilir (saveAll)
 * -> SecurityContext.clearContext()
 * -> Response: 200 OK
 * </pre>
 * </p>
 *
 * <p><b>🔴 GÜVENLİK SORUNU (ESKİ KOD):</b>
 * <pre>
 * // ❌ YANLIŞ: Sadece gönderilen token revoke ediliyor
 * var storedToken = tokenRepository.findByToken(jwt).orElse(null);
 * if (storedToken != null) {
 *   storedToken.setExpired(true);
 *   storedToken.setRevoked(true);
 *   tokenRepository.save(storedToken);
 * }
 *
 * // SORUN: Refresh token hala geçerli!
 * // Attacker refresh token ile yeni access token alabilir!
 * </pre>
 * </p>
 *
 * <p><b>✅ DOĞRU ÇÖZÜM (YENİ KOD):</b>
 * <pre>
 * // ✅ DOĞRU: User'ın TÜM token'ları revoke ediliyor
 * var storedToken = tokenRepository.findByToken(jwt).orElse(null);
 * if (storedToken != null) {
 *   var allUserTokens = tokenRepository.findAllValidTokenByUser(
 *       storedToken.getUser().getId()
 *   );
 *   allUserTokens.forEach(token -> {
 *     token.setExpired(true);
 *     token.setRevoked(true);
 *   });
 *   tokenRepository.saveAll(allUserTokens);
 * }
 *
 * // SONUÇ: Refresh token da revoke edildi!
 * // Attacker refresh token ile yeni access token alamaz!
 * </pre>
 * </p>
 *
 * <p><b>🔥 NEDEN TÜM TOKEN'LARI REVOKE EDİYORUZ?</b>
 * <ul>
 *   <li><b>Güvenlik:</b> Logout sonrası hiçbir token geçerli olmamalı</li>
 *   <li><b>Refresh Token:</b> Refresh token ile yeni access token alınmasını engelle</li>
 *   <li><b>Multi-Device Logout:</b> Tüm cihazlardan logout yap</li>
 *   <li><b>Stolen Token:</b> Çalınan refresh token ile erişimi engelle</li>
 * </ul>
 * </p>
 *
 * <p><b>SENARYO: Çalınan Refresh Token</b>
 * <pre>
 * 1. User login yaptı
 *    -> access_token: "abc123"
 *    -> refresh_token: "xyz789"
 *
 * 2. Attacker refresh token'ı çaldı (XSS, network sniffing, vb.)
 *
 * 3. User logout yaptı (access token ile)
 *
 * 4. ESKİ KOD (YANLIŞ):
 *    -> Sadece access_token revoke edildi
 *    -> refresh_token hala geçerli! ❌
 *    -> Attacker refresh token ile yeni access token alabilir! 🔴
 *
 * 5. YENİ KOD (DOĞRU):
 *    -> TÜM token'lar revoke edildi (access + refresh) ✅
 *    -> refresh_token artık geçersiz! ✅
 *    -> Attacker refresh token ile yeni access token alamaz! ✅
 * </pre>
 * </p>
 *
 * <p><b>SPRING SECURITY ENTEGRASYONU:</b>
 * SecurityConfiguration'da logout handler olarak register edilir:
 * <pre>
 * .logout()
 *     .logoutUrl("/api/v1/auth/logout")
 *     .addLogoutHandler(logoutHandler)
 *     .logoutSuccessHandler(...)
 * </pre>
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Exception handling ekle (token bulunamazsa ne olacak)
 * - Audit logging ekle (kim ne zaman logout oldu)
 * - Logout sonrası redirect URL ekle
 * - Selective logout ekle (sadece bu cihazdan çık vs tüm cihazlardan çık)
 * </p>
 *
 * @author Gokhan Degerli
 * @version 2.0 (Security fix: Revoke all user tokens)
 * @see LogoutHandler Spring Security'nin logout interface'i
 * @see SecurityConfiguration Logout handler'ı register eden config
 * @see TokenRepository Token DB işlemleri
 */
@Service
@RequiredArgsConstructor // Lombok: final field için constructor
public class LogoutService implements LogoutHandler {

  /**
   * Token repository'si
   *
   * <p>Token'ı DB'den bulma ve güncelleme işlemleri için kullanılır.</p>
   */
  private final TokenRepository tokenRepository;

  /**
   * Logout işlemini gerçekleştirir
   *
   * <p><b>NE:</b> Authorization header'ından token'ı alır, user'ın TÜM token'larını bulur ve revoke eder.</p>
   *
   * <p><b>AKIŞ:</b>
   * 1. Request'ten Authorization header alınır
   * 2. Header yoksa veya "Bearer " ile başlamıyorsa işlem yapılmaz (early return)
   * 3. "Bearer " prefix'i kaldırılır, JWT token çıkarılır
   * 4. Token DB'den bulunur (tokenRepository.findByToken)
   * 5. Token bulunamazsa işlem yapılmaz (early return)
   * 6. Token'ın sahibi olan user'ın TÜM geçerli token'ları bulunur (findAllValidTokenByUser)
   * 7. TÜM token'lar expired ve revoked true yapılır (forEach)
   * 8. Token'lar DB'ye kaydedilir (saveAll - batch operation)
   * 9. SecurityContext temizlenir (kullanıcı oturumu sonlandırılır)
   * </p>
   *
   * <p><b>AUTHORIZATION HEADER:</b>
   * <pre>
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   *                ^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   *                prefix JWT token
   * </pre>
   * </p>
   *
   * <p><b>TOKEN REVOKE (TÜM TOKEN'LAR):</b>
   * User'ın TÜM token'ları DB'de şu şekilde güncellenir:
   * <pre>
   * // ACCESS TOKEN
   * Token {
   *   token: "access_abc123",
   *   tokenPurpose: ACCESS,
   *   expired: false -> true   // Token süresi doldu olarak işaretle
   *   revoked: false -> true   // Token iptal edildi olarak işaretle
   * }
   *
   * // REFRESH TOKEN
   * Token {
   *   token: "refresh_xyz789",
   *   tokenPurpose: REFRESH,
   *   expired: false -> true   // Token süresi doldu olarak işaretle
   *   revoked: false -> true   // Token iptal edildi olarak işaretle
   * }
   * </pre>
   * </p>
   *
   * <p><b>SECURITY CONTEXT CLEAR:</b>
   * SecurityContextHolder.clearContext() çağrılır.
   * Bu sayede:
   * - Kullanıcı oturumu sonlandırılır
   * - SecurityContext'teki Authentication objesi temizlenir
   * - Sonraki request'lerde kullanıcı authenticated olmaz
   * </p>
   *
   * <p><b>NEDEN EARLY RETURN KULLANILIYOR:</b>
   * <pre>
   * // ❌ YANLIŞ: Nested if'ler (okunması zor)
   * if (authHeader != null) {
   *   if (authHeader.startsWith("Bearer ")) {
   *     String jwt = authHeader.substring(7);
   *     var storedToken = tokenRepository.findByToken(jwt).orElse(null);
   *     if (storedToken != null) {
   *       // ...
   *     }
   *   }
   * }
   *
   * // ✅ DOĞRU: Early return (okunması kolay)
   * if (authHeader == null || !authHeader.startsWith("Bearer ")) {
   *   return; // Hemen çık
   * }
   * String jwt = authHeader.substring(7);
   * var storedToken = tokenRepository.findByToken(jwt).orElse(null);
   * if (storedToken == null) {
   *   return; // Hemen çık
   * }
   * // ...
   * </pre>
   * </p>
   *
   * <p><b>NEDEN saveAll KULLANILIYOR:</b>
   * <pre>
   * // ❌ YANLIŞ: Her token için ayrı DB query (N+1 problem)
   * allUserTokens.forEach(token -> {
   *   token.setExpired(true);
   *   token.setRevoked(true);
   *   tokenRepository.save(token); // Her token için ayrı query!
   * });
   *
   * // ✅ DOĞRU: Batch operation (tek query)
   * allUserTokens.forEach(token -> {
   *   token.setExpired(true);
   *   token.setRevoked(true);
   * });
   * tokenRepository.saveAll(allUserTokens); // Tek query ile tüm token'lar!
   * </pre>
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * // 1. User login yaptı
   * POST /api/v1/auth/authenticate
   * Response: {
   *   "access_token": "access_abc123",
   *   "refresh_token": "refresh_xyz789"
   * }
   *
   * // 2. DB'ye bak
   * SELECT * FROM token WHERE user_id = 1;
   * // access_abc123 (expired=false, revoked=false, purpose=ACCESS)
   * // refresh_xyz789 (expired=false, revoked=false, purpose=REFRESH)
   *
   * // 3. User logout yaptı
   * POST /api/v1/auth/logout
   * Authorization: Bearer access_abc123
   *
   * // 4. LogoutService.logout() çağrıldı
   * // -> Token bulundu: access_abc123
   * // -> User'ın TÜM token'ları bulundu: [access_abc123, refresh_xyz789]
   * // -> TÜM token'lar revoke edildi
   * // -> SecurityContext temizlendi
   *
   * // 5. DB'ye tekrar bak
   * SELECT * FROM token WHERE user_id = 1;
   * // access_abc123 (expired=true, revoked=true, purpose=ACCESS) ✅
   * // refresh_xyz789 (expired=true, revoked=true, purpose=REFRESH) ✅
   *
   * // 6. Attacker refresh token ile yeni access token almayı denedi
   * POST /api/v1/auth/refresh-token
   * Authorization: Bearer refresh_xyz789
   * Response: 403 Forbidden ✅ (Token revoked!)
   * </pre>
   * </p>
   *
   * <p><b>TODO:</b>
   * - Token bulunamazsa exception fırlat (veya log at)
   * - Audit logging ekle (kim ne zaman logout oldu)
   * - Selective logout ekle (sadece bu cihazdan çık vs tüm cihazlardan çık)
   * - Logout sonrası redirect URL ekle
   * </p>
   *
   * <p><b>KULLANIM YERİ:</b>
   * - SecurityConfiguration: Logout handler olarak register edilir
   * - POST /api/v1/auth/logout endpoint'i
   * </p>
   *
   * @param request        HTTP request (Authorization header'ından token alınır)
   * @param response       HTTP response (kullanılmıyor)
   * @param authentication Authentication objesi (kullanılmıyor, null olabilir)
   * @see TokenRepository#findByToken(String) Token'ı DB'den bulan method
   * @see TokenRepository#findAllValidTokenByUser(Integer) User'ın TÜM geçerli token'larını bulan method
   * @see SecurityContextHolder#clearContext() SecurityContext'i temizleyen method
   */
  @Override
  public void logout(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) {
    // 1. Request'ten Authorization header'ı al
    final String authHeader = request.getHeader("Authorization");

    // 2. Authorization header yoksa veya "Bearer " ile başlamıyorsa işlem yapma
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return; // Early return (sessizce çık)
    }

    // 3. "Bearer " prefix'ini kaldır, JWT token'ı al
    final String jwt = authHeader.substring(7); // "Bearer " 7 karakter

    // 4. Token'ı DB'den bul
    var storedToken = tokenRepository.findByToken(jwt).orElse(null);

    // 5. Token bulunamazsa işlem yapma
    if (storedToken == null) {
      return; // Early return (token bulunamadı)
    }

    // 6. User'ın TÜM geçerli token'larını bul (ACCESS + REFRESH)
    // ⚠️ KRİTİK: Sadece gönderilen token'ı değil, TÜM token'ları revoke et!
    var allUserTokens = tokenRepository.findAllValidTokenByUser(
        storedToken.getUser().getId()
    );

    // 7. TÜM token'ları expired ve revoked olarak işaretle
    allUserTokens.forEach(token -> {
      token.setExpired(true);  // Token süresi doldu
      token.setRevoked(true);  // Token iptal edildi
    });

    // 8. TÜM token'ları DB'ye kaydet (batch operation)
    tokenRepository.saveAll(allUserTokens);

    // 9. SecurityContext'i temizle (kullanıcı oturumunu sonlandır)
    SecurityContextHolder.clearContext();
  }
}