package com.degerli.security.user;

import java.security.Principal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * UserService - Kullanıcı İşlemleri Servisi
 *
 * <p><b>NE:</b> Kullanıcı ile ilgili business logic işlemlerini yöneten servis.
 * Şu anda sadece şifre değiştirme özelliği var.</p>
 *
 * <p><b>NEDEN:</b>
 * - Kullanıcı işlemlerini controller'dan ayırmak (separation of concerns)
 * - Business logic'i merkezi bir yerden yönetmek
 * - Şifre değiştirme işlemini güvenli yapmak
 * </p>
 *
 * <p><b>NASIL ÇALIŞIR:</b>
 * 1. Client ChangePasswordRequest gönderir (currentPassword, newPassword,
 * confirmationPassword)
 * 2. Principal'dan authenticated user alınır
 * 3. Mevcut şifre kontrol edilir
 * 4. Yeni şifreler eşleşiyor mu kontrol edilir
 * 5. Yeni şifre hash'lenir ve DB'ye kaydedilir
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Password strength validation ekle
 * - Şifre geçmişi tut (aynı şifre tekrar kullanılmasın)
 * - Email notification ekle (şifre değiştirildi bildirimi)
 * - Audit logging ekle (kim ne zaman şifre değiştirdi)
 * - Custom exception'lar ekle (IllegalStateException yerine)
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see UserController Şifre değiştirme endpoint'i
 * @see ChangePasswordRequest Şifre değiştirme request DTO'su
 */
@Service
@RequiredArgsConstructor // Lombok: final field'lar için constructor
public class UserService {

  /**
   * Şifre encoder (BCrypt)
   *
   * <p>Şifreleri hash'lemek ve kontrol etmek için kullanılır.</p>
   */
  private final PasswordEncoder passwordEncoder;

  /**
   * Kullanıcı repository'si
   *
   * <p>Kullanıcı güncelleme işlemleri için kullanılır.</p>
   */
  private final UserRepository repository;

  /**
   * Kullanıcının şifresini değiştirir
   *
   * <p><b>NE:</b> Authenticated user'ın şifresini güvenli bir şekilde değiştirir.</p>
   *
   * <p><b>AKIŞ:</b>
   * 1. Principal'dan authenticated user alınır (cast: UsernamePasswordAuthenticationToken)
   * 2. Mevcut şifre kontrol edilir (passwordEncoder.matches)
   * 3. Yeni şifreler eşleşiyor mu kontrol edilir
   * 4. Yeni şifre BCrypt ile hash'lenir
   * 5. User entity güncellenir ve DB'ye kaydedilir
   * </p>
   *
   * <p><b>PRINCIPAL NEDİR:</b>
   * - Spring Security'nin authenticated user'ı temsil eden interface'i
   * - SecurityContext'ten alınır (SecurityContextHolder.getContext().getAuthentication())
   * - Controller method'larına @AuthenticationPrincipal veya Principal parameter ile inject
   * edilir
   * - Cast edilerek User entity'sine çevrilebilir
   * </p>
   *
   * <p><b>NASIL ÇALIŞIR:</b>
   * <pre>
   * // 1. Principal'dan Authentication objesi alınır
   * UsernamePasswordAuthenticationToken authToken = (UsernamePasswordAuthenticationToken) connectedUser;
   *
   * // 2. Authentication'dan User entity alınır
   * User user = (User) authToken.getPrincipal();
   *
   * // 3. User'ın şifresi güncellenir
   * user.setPassword(newHashedPassword);
   * repository.save(user);
   * </pre>
   * </p>
   *
   * <p><b>VALIDATION:</b>
   * 1. Mevcut şifre doğru mu? (passwordEncoder.matches)
   * 2. Yeni şifreler eşleşiyor mu? (newPassword.equals(confirmationPassword))
   * 3. Her iki kontrol de geçerse şifre değiştirilir
   * </p>
   *
   * <p><b>GÜVENLİK:</b>
   * - Mevcut şifre kontrol edilir (başkası şifre değiştiremesin)
   * - Yeni şifre BCrypt ile hash'lenir (plain text saklanmaz)
   * - Authenticated user'ın kendi şifresini değiştirir (başkasının değil)
   * </p>
   *
   * <p><b>EXCEPTION'LAR:</b>
   * - IllegalStateException("Wrong password"): Mevcut şifre yanlış
   * - IllegalStateException("Password are not the same"): Yeni şifreler eşleşmiyor
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * ChangePasswordRequest request = ChangePasswordRequest.builder()
   *     .currentPassword("oldPassword123")
   *     .newPassword("newPassword456")
   *     .confirmationPassword("newPassword456")
   *     .build();
   *
   * userService.changePassword(request, principal);
   * // Şifre başarıyla değiştirildi
   * </pre>
   * </p>
   *
   * <p><b>TODO:</b>
   * - Custom exception'lar ekle (WrongPasswordException, PasswordMismatchException)
   * - Password strength validation ekle (min 8 karakter, büyük harf, rakam, özel karakter)
   * - Şifre geçmişi tut (son 5 şifre tekrar kullanılmasın)
   * - Email notification ekle (şifre değiştirildi bildirimi)
   * - Audit logging ekle (kim ne zaman şifre değiştirdi)
   * - Token'ları revoke et (şifre değişince tüm token'lar geçersiz olsun)
   * </p>
   *
   * <p><b>KULLANIM YERİ:</b>
   * - UserController.changePassword(): PATCH /api/v1/users
   * </p>
   *
   * @param request       Şifre değiştirme bilgileri (currentPassword, newPassword,
   *                      confirmationPassword)
   * @param connectedUser Authenticated user (Principal)
   * @throws IllegalStateException Mevcut şifre yanlış veya yeni şifreler eşleşmiyor
   * @see ChangePasswordRequest Şifre değiştirme request DTO'su
   * @see Principal Spring Security'nin authenticated user interface'i
   */
  public void changePassword(ChangePasswordRequest request, Principal connectedUser) {
    // 1. Principal'dan authenticated user'ı al (cast: UsernamePasswordAuthenticationToken
    // -> User)
    var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

    // 2. Mevcut şifre doğru mu kontrol et
    if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
      throw new IllegalStateException("Wrong password"); // Mevcut şifre yanlış
    }

    // 3. Yeni şifreler eşleşiyor mu kontrol et
    if (!request.getNewPassword().equals(request.getConfirmationPassword())) {
      throw new IllegalStateException("Password are not the same"); // Yeni şifreler eşleşmiyor
    }

    // 4. Yeni şifreyi hash'le ve user'a set et
    user.setPassword(passwordEncoder.encode(request.getNewPassword()));

    // 5. User'ı DB'ye kaydet (şifre güncellendi)
    repository.save(user);
  }
}