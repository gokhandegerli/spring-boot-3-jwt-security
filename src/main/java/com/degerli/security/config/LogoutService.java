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
 * </p>
 *
 * <p><b>NASIL ÇALIŞIR:</b>
 * 1. Client logout endpoint'ine request gönderir (Authorization header'ında token)
 * 2. LogoutService.logout() method'u çağrılır
 * 3. Authorization header'ından token çıkarılır
 * 4. Token DB'den bulunur
 * 5. Token expired ve revoked olarak işaretlenir
 * 6. SecurityContext temizlenir (kullanıcı oturumu sonlandırılır)
 * </p>
 *
 * <p><b>LOGOUT AKIŞI:</b>
 * <pre>
 * POST /api/v1/auth/logout
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *
 * -> LogoutService.logout() çağrılır
 * -> Token DB'den bulunur
 * -> Token.expired = true, Token.revoked = true
 * -> Token DB'ye kaydedilir
 * -> SecurityContext.clearContext()
 * -> Response: 200 OK
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
 * - Tüm cihazlardan logout özelliği ekle (revokeAllUserTokens)
 * - Logout sonrası redirect URL ekle
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
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
   * <p><b>NE:</b> Authorization header'ından token'ı alır, DB'de bulur ve revoke eder.</p>
   *
   * <p><b>AKIŞ:</b>
   * 1. Request'ten Authorization header alınır
   * 2. Header yoksa veya "Bearer " ile başlamıyorsa işlem yapılmaz
   * 3. "Bearer " prefix'i kaldırılır, JWT token çıkarılır
   * 4. Token DB'den bulunur (tokenRepository.findByToken)
   * 5. Token bulunursa expired ve revoked true yapılır
   * 6. Token DB'ye kaydedilir
   * 7. SecurityContext temizlenir (kullanıcı oturumu sonlandırılır)
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
   * <p><b>TOKEN REVOKE:</b>
   * Token DB'de şu şekilde güncellenir:
   * <pre>
   * Token {
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
   * <p><b>NEDEN ifPresent KULLANILIYOR:</b>
   * tokenRepository.findByToken() Optional döner.
   * Token bulunursa ifPresent içindeki kod çalışır, bulunamazsa hiçbir şey olmaz.
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * // Client logout request gönderir
   * POST /api/v1/auth/logout
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   *
   * // LogoutService.logout() çağrılır
   * // Token DB'de revoke edilir
   * // SecurityContext temizlenir
   * // Response: 200 OK
   * </pre>
   * </p>
   *
   * <p><b>TODO:</b>
   * - Token bulunamazsa exception fırlat (veya log at)
   * - Audit logging ekle (kim ne zaman logout oldu)
   * - Tüm cihazlardan logout özelliği ekle
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
   * @param authentication Authentication objesi (kullanılmıyor)
   * @see TokenRepository#findByToken(String) Token'ı DB'den bulan method
   * @see SecurityContextHolder#clearContext() SecurityContext'i temizleyen method
   */
  @Override
  public void logout(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) {
    // 1. Request'ten Authorization header'ı al
    final String authHeader = request.getHeader("Authorization");
    final String jwt;

    // 2. Authorization header yoksa veya "Bearer " ile başlamıyorsa işlem yapma
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return; // Early return (sessizce çık)
    }

    // 3. "Bearer " prefix'ini kaldır, JWT token'ı al
    jwt = authHeader.substring(7); // "Bearer " 7 karakter

    // 4. Token'ı DB'den bul
    var storedToken = tokenRepository.findByToken(jwt)
        .orElse(null); // Token bulunamazsa null döner

    // 5. Token bulunduysa expired ve revoked olarak işaretle
    if (storedToken != null) {
      storedToken.setExpired(true);  // Token süresi doldu
      storedToken.setRevoked(true);  // Token iptal edildi
      tokenRepository.save(storedToken); // Token'ı DB'ye kaydet

      // 6. SecurityContext'i temizle (kullanıcı oturumunu sonlandır)
      SecurityContextHolder.clearContext();
    }
  }
}