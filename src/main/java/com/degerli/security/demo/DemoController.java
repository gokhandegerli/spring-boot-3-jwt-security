package com.degerli.security.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * DemoController - Demo REST Controller
 *
 * <p><b>NE:</b> Demo amaçlı basit bir endpoint sağlar.
 * JWT authentication'ın çalıştığını test etmek için kullanılır.</p>
 *
 * <p><b>NEDEN:</b>
 * - JWT authentication'ı test etmek
 * - Secured endpoint örneği göstermek
 * - Basit bir "Hello World" endpoint'i sağlamak
 * </p>
 *
 * <p><b>ENDPOINT:</b>
 *
 * <b>GET /api/v1/demo-controller</b>
 * - Demo endpoint
 * - Response: "Hello from secured endpoint"
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
 * // 1. Login yap ve token al
 * POST /api/v1/auth/authenticate
 * {
 *   "email": "admin@mail.com",
 *   "password": "password"
 * }
 * Response: { "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }
 *
 * // 2. Token ile demo endpoint'e istek at
 * GET /api/v1/demo-controller
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * Response: 200 OK
 * "Hello from secured endpoint"
 *
 * // 3. Token olmadan istek at
 * GET /api/v1/demo-controller
 * Response: 403 Forbidden (veya 401 Unauthorized)
 * </pre>
 * </p>
 *
 * <p><b>TEST SENARYOLARI:</b>
 * 1. Token ile istek at -> 200 OK
 * 2. Token olmadan istek at -> 403 Forbidden
 * 3. Expired token ile istek at -> 403 Forbidden
 * 4. Invalid token ile istek at -> 403 Forbidden
 * </p>
 *
 * <p><b>TODO:</b>
 * - Authenticated user bilgilerini döndür (Principal parameter ekle)
 * - Farklı roller için farklı response'lar döndür
 * - Exception handling ekle
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see SecurityConfiguration JWT authentication config
 */
@RestController // REST API controller
@RequestMapping("/api/v1/demo-controller") // Base path: /api/v1/demo-controller
public class DemoController {

  /**
   * Demo endpoint
   *
   * <p><b>NE:</b> Basit bir "Hello World" mesajı döner.</p>
   *
   * <p><b>HTTP METHOD:</b> GET</p>
   * <p><b>PATH:</b> /api/v1/demo-controller</p>
   * <p><b>RESPONSE:</b> String (plain text)</p>
   * <p><b>AUTHENTICATION:</b> Gerekli (JWT token)</p>
   *
   * <p><b>AMAÇ:</b>
   * JWT authentication'ın çalıştığını test etmek.
   * Token ile istek atıldığında 200 OK, token olmadan 403 Forbidden döner.
   * </p>
   *
   * <p><b>REQUEST ÖRNEĞİ:</b>
   * <pre>
   * GET /api/v1/demo-controller
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   * </pre>
   * </p>
   *
   * <p><b>RESPONSE ÖRNEĞİ:</b>
   * <pre>
   * 200 OK
   * "Hello from secured endpoint"
   * </pre>
   * </p>
   *
   * <p><b>TODO:</b>
   * - Authenticated user bilgilerini döndür (Principal parameter ekle)
   * - JSON response döndür (String yerine)
   * </p>
   *
   * @return "Hello from secured endpoint" mesajı
   */
  @GetMapping
  public ResponseEntity<String> sayHello() {
    return ResponseEntity.ok("Hello from secured endpoint");
  }
}