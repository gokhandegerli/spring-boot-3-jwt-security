package com.degerli.security.user;

import java.security.Principal;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * UserController - Kullanıcı İşlemleri REST Controller
 *
 * <p><b>NE:</b> Kullanıcı ile ilgili işlemleri sağlayan REST API controller.
 * Şu anda sadece şifre değiştirme endpoint'i var.</p>
 *
 * <p><b>NEDEN:</b>
 * - Authenticated user'ların kendi bilgilerini yönetebilmesi
 * - Şifre değiştirme özelliği sağlamak
 * - User management endpoint'leri sunmak
 * </p>
 *
 * <p><b>ENDPOINT'LER:</b>
 *
 * <b>PATCH /api/v1/users</b>
 * - Şifre değiştirme
 * - Request: ChangePasswordRequest (currentPassword, newPassword, confirmationPassword)
 * - Response: 200 OK
 * - Authentication gerektirir (JWT token)
 * </p>
 *
 * <p><b>SECURITY:</b>
 * Bu endpoint authenticated user'lar tarafından erişilebilir.
 * SecurityConfiguration'da korunur:
 * <pre>
 * .anyRequest().authenticated()
 * </pre>
 * </p>
 *
 * <p><b>KULLANIM ÖRNEĞİ:</b>
 * <pre>
 * PATCH /api/v1/users
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * Content-Type: application/json
 * {
 *   "currentPassword": "oldPassword123",
 *   "newPassword": "newPassword456",
 *   "confirmationPassword": "newPassword456"
 * }
 *
 * Response: 200 OK
 * </pre>
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - GET /api/v1/users/me endpoint'i ekle (kullanıcı bilgilerini getir)
 * - PUT /api/v1/users endpoint'i ekle (kullanıcı bilgilerini güncelle)
 * - DELETE /api/v1/users endpoint'i ekle (hesap silme)
 * - Validation ekle (@Valid annotation)
 * - Exception handling ekle (@ExceptionHandler)
 * - DTO kullan (User entity'sini direkt dönme)
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see UserService Kullanıcı business logic
 * @see ChangePasswordRequest Şifre değiştirme request DTO'su
 */
@RestController // REST API controller
@RequestMapping("/api/v1/users") // Base path: /api/v1/users
@RequiredArgsConstructor // Lombok: final field için constructor
public class UserController {

  /**
   * Kullanıcı servisi
   *
   * <p>Kullanıcı işlemlerini yöneten servis (şifre değiştirme, vb.).</p>
   */
  private final UserService service;

  /**
   * Şifre değiştirme endpoint'i
   *
   * <p><b>NE:</b> Authenticated user'ın şifresini değiştirir.</p>
   *
   * <p><b>HTTP METHOD:</b> PATCH (partial update)</p>
   * <p><b>PATH:</b> /api/v1/users</p>
   * <p><b>REQUEST BODY:</b> ChangePasswordRequest (JSON)</p>
   * <p><b>RESPONSE:</b> 200 OK</p>
   * <p><b>AUTHENTICATION:</b> Gerekli (JWT token)</p>
   *
   * <p><b>NEDEN PATCH:</b>
   * - PATCH: Partial update (sadece şifre değiştiriliyor)
   * - PUT: Full update (tüm user bilgileri gönderilmeli)
   * - POST: Create (yeni kaynak oluşturma)
   * </p>
   *
   * <p><b>PRINCIPAL NEDİR:</b>
   * - Spring Security'nin authenticated user'ı temsil eden interface'i
   * - SecurityContext'ten otomatik inject edilir
   * - Method parameter olarak alınır
   * - Cast edilerek User entity'sine çevrilebilir
   * </p>
   *
   * <p><b>REQUEST ÖRNEĞİ:</b>
   * <pre>
   * PATCH /api/v1/users
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   * Content-Type: application/json
   * {
   *   "currentPassword": "oldPassword123",
   *   "newPassword": "newPassword456",
   *   "confirmationPassword": "newPassword456"
   * }
   * </pre>
   * </p>
   *
   * <p><b>RESPONSE ÖRNEĞİ:</b>
   * <pre>
   * 200 OK
   * </pre>
   * </p>
   *
   * <p><b>EXCEPTION'LAR:</b>
   * - IllegalStateException("Wrong password"): Mevcut şifre yanlış
   * - IllegalStateException("Password are not the same"): Yeni şifreler eşleşmiyor
   * </p>
   *
   * <p><b>TODO:</b>
   * - @Valid ekle (request validation)
   * - Exception handling ekle (custom error response)
   * - Success message döndür (ResponseEntity<String>)
   * - Audit logging ekle (kim ne zaman şifre değiştirdi)
   * </p>
   *
   * @param request       Şifre değiştirme bilgileri (currentPassword, newPassword,
   *                      confirmationPassword)
   * @param connectedUser Authenticated user (Principal - Spring Security tarafından inject
   *                      edilir)
   * @return 200 OK response
   * @see ChangePasswordRequest Şifre değiştirme request DTO'su
   * @see UserService#changePassword(ChangePasswordRequest, Principal) Şifre değiştirme
   * business logic
   * @see Principal Spring Security'nin authenticated user interface'i
   */
  @PatchMapping
  public ResponseEntity<?> changePassword(
      @RequestBody
      ChangePasswordRequest request,
      // JSON request body'den ChangePasswordRequest parse edilir
      Principal connectedUser
      // Authenticated user (Spring Security tarafından inject edilir)
  ) {
    // UserService.changePassword() çağrılır
    service.changePassword(request, connectedUser);

    // 200 OK response döner (body yok)
    return ResponseEntity.ok().build();
  }
}