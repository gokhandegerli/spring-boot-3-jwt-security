package com.degerli.security.book;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * BookController - Kitap İşlemleri REST Controller
 *
 * <p><b>NE:</b> Kitap ile ilgili CRUD operasyonlarını sağlayan REST API controller.
 * Kitap kaydetme, listeleme ve ID ile bulma endpoint'lerini sunar.</p>
 *
 * <p><b>NEDEN:</b>
 * - Kitap yönetimi için REST API sağlamak
 * - CRUD operasyonları sunmak
 * - Demo amaçlı örnek entity ve endpoint'ler göstermek
 * </p>
 *
 * <p><b>ENDPOINT'LER:</b>
 *
 * <b>1. POST /api/v1/books</b>
 * - Yeni kitap kaydetme
 * - Request: BookRequest (author, isbn)
 * - Response: 200 OK
 * - Authentication gerektirir (JWT token)
 *
 * <b>2. GET /api/v1/books</b>
 * - Tüm kitapları listeleme
 * - Response: List<Book>
 * - Authentication gerektirir (JWT token)
 *
 * <b>3. GET /api/v1/books/{book-id}</b>
 * - ID ile kitap bulma
 * - Path Variable: book-id
 * - Response: Book
 * - Authentication gerektirir (JWT token)
 * </p>
 *
 * <p><b>SECURITY:</b>
 * Bu endpoint'ler authenticated user'lar tarafından erişilebilir.
 * SecurityConfiguration'da korunur:
 * <pre>
 * .anyRequest().authenticated()
 * </pre>
 * </p>
 *
 * <p><b>KULLANIM ÖRNEĞİ:</b>
 * <pre>
 * // 1. SAVE
 * POST /api/v1/books
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * Content-Type: application/json
 * {
 *   "author": "Gokhan Degerli",
 *   "isbn": "978-3-16-148410-0"
 * }
 * Response: 200 OK
 *
 * // 2. FIND ALL
 * GET /api/v1/books
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * Response: 200 OK
 * [
 *   {
 *     "id": 1,
 *     "author": "Gokhan Degerli",
 *     "isbn": "978-3-16-148410-0"
 *   }
 * ]
 *
 * // 3. FIND BY ID
 * GET /api/v1/books/1
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * Response: 200 OK
 * {
 *   "id": 1,
 *   "author": "Gokhan Degerli",
 *   "isbn": "978-3-16-148410-0"
 * }
 * </pre>
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - PUT /api/v1/books/{id} endpoint'i ekle (kitap güncelleme)
 * - DELETE /api/v1/books/{id} endpoint'i ekle (kitap silme)
 * - Pagination ekle (GET /api/v1/books?page=0&size=10)
 * - Filtering ekle (GET /api/v1/books?author=Gokhan)
 * - Sorting ekle (GET /api/v1/books?sort=author,asc)
 * - Validation ekle (@Valid annotation)
 * - Exception handling ekle (@ExceptionHandler)
 * - DTO kullan (Book entity'sini direkt dönme)
 * - HATEOAS ekle (self link, vb.)
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see BookService Kitap business logic
 * @see BookRequest Kitap request DTO'su
 * @see Book Kitap entity'si
 */
@RestController // REST API controller
@RequestMapping("/api/v1/books") // Base path: /api/v1/books
@RequiredArgsConstructor // Lombok: final field için constructor
public class BookController {

  /**
   * Kitap servisi
   *
   * <p>Kitap işlemlerini yöneten servis (CRUD operasyonları).</p>
   */
  private final BookService service;

  /**
   * Yeni kitap kaydetme endpoint'i
   *
   * <p><b>NE:</b> Yeni kitap kaydeder ve 200 OK döner.</p>
   *
   * <p><b>HTTP METHOD:</b> POST</p>
   * <p><b>PATH:</b> /api/v1/books</p>
   * <p><b>REQUEST BODY:</b> BookRequest (JSON)</p>
   * <p><b>RESPONSE:</b> 200 OK</p>
   * <p><b>AUTHENTICATION:</b> Gerekli (JWT token)</p>
   *
   * <p><b>REQUEST ÖRNEĞİ:</b>
   * <pre>
   * POST /api/v1/books
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   * Content-Type: application/json
   * {
   *   "author": "Gokhan Degerli",
   *   "isbn": "978-3-16-148410-0"
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
   * <p><b>TODO:</b>
   * - @Valid ekle (request validation)
   * - 201 CREATED döndür (200 OK yerine)
   * - Location header ekle (yeni kaynağın URL'i)
   * - Kaydedilen kitabı döndür (ResponseEntity<Book>)
   * - Exception handling ekle (duplicate ISBN, vb.)
   * </p>
   *
   * @param request Kitap bilgileri (author, isbn)
   * @return 200 OK response
   * @see BookRequest Kitap request DTO'su
   * @see BookService#save(BookRequest) Kitap kaydetme business logic
   */
  @PostMapping
  public ResponseEntity<?> save(
      @RequestBody
      BookRequest request // JSON request body'den BookRequest parse edilir
  ) {
    // BookService.save() çağrılır
    service.save(request);

    // 200 OK response döner (body yok)
    return ResponseEntity.ok().build();
  }

  /**
   * Tüm kitapları listeleme endpoint'i
   *
   * <p><b>NE:</b> DB'deki tüm kitapları liste olarak döner.</p>
   *
   * <p><b>HTTP METHOD:</b> GET</p>
   * <p><b>PATH:</b> /api/v1/books</p>
   * <p><b>RESPONSE:</b> List<Book> (JSON)</p>
   * <p><b>AUTHENTICATION:</b> Gerekli (JWT token)</p>
   *
   * <p><b>PERFORMANS UYARISI:</b>
   * Tüm kitapları getirir. DB'de çok fazla kitap varsa performans sorunu olabilir.
   * Pagination kullanılması önerilir.
   * </p>
   *
   * <p><b>REQUEST ÖRNEĞİ:</b>
   * <pre>
   * GET /api/v1/books
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   * </pre>
   * </p>
   *
   * <p><b>RESPONSE ÖRNEĞİ:</b>
   * <pre>
   * 200 OK
   * [
   *   {
   *     "id": 1,
   *     "author": "Gokhan Degerli",
   *     "isbn": "978-3-16-148410-0"
   *   },
   *   {
   *     "id": 2,
   *     "author": "John Doe",
   *     "isbn": "978-1-23-456789-0"
   *   }
   * ]
   * </pre>
   * </p>
   *
   * <p><b>TODO:</b>
   * - Pagination ekle (Pageable parameter)
   * - Filtering ekle (author, isbn, vb.)
   * - Sorting ekle (Sort parameter)
   * - DTO kullan (Book entity'sini direkt dönme)
   * - Cache ekle (@Cacheable annotation)
   * </p>
   *
   * @return Tüm kitapların listesi
   * @see Book Kitap entity'si
   * @see BookService#findAll() Tüm kitapları getiren business logic
   */
  @GetMapping
  public ResponseEntity<List<Book>> findAllBooks() {
    // BookService.findAll() çağrılır ve liste döner
    return ResponseEntity.ok(service.findAll());
  }

  /**
   * ID ile kitap bulma endpoint'i
   *
   * <p><b>NE:</b> Verilen ID'ye sahip kitabı bulur ve döner.</p>
   *
   * <p><b>HTTP METHOD:</b> GET</p>
   * <p><b>PATH:</b> /api/v1/books/{book-id}</p>
   * <p><b>PATH VARIABLE:</b> book-id (Integer)</p>
   * <p><b>RESPONSE:</b> Book (JSON)</p>
   * <p><b>AUTHENTICATION:</b> Gerekli (JWT token)</p>
   *
   * <p><b>PATH VARIABLE NEDİR:</b>
   * - URL'in bir parçası olarak gönderilen değişken
   * - @PathVariable annotation ile alınır
   * - Örnek: /api/v1/books/1 -> book-id = 1
   * </p>
   *
   * <p><b>REQUEST ÖRNEĞİ:</b>
   * <pre>
   * GET /api/v1/books/1
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   * </pre>
   * </p>
   *
   * <p><b>RESPONSE ÖRNEĞİ:</b>
   * <pre>
   * 200 OK
   * {
   *   "id": 1,
   *   "author": "Gokhan Degerli",
   *   "isbn": "978-3-16-148410-0"
   * }
   * </pre>
   * </p>
   *
   * <p><b>EXCEPTION:</b>
   * - NoSuchElementException: Kitap bulunamazsa (500 Internal Server Error)
   * </p>
   *
   * <p><b>TODO:</b>
   * - Exception handling ekle (404 Not Found döndür)
   * - DTO kullan (Book entity'sini direkt dönme)
   * - Cache ekle (@Cacheable annotation)
   * - HATEOAS ekle (self link, vb.)
   * </p>
   *
   * @param bookId Kitap ID'si (path variable)
   * @return Bulunan kitap
   * @see Book Kitap entity'si
   * @see BookService#findById(Integer) ID ile kitap bulan business logic
   */
  @GetMapping("/{book-id}")
  public ResponseEntity<Book> findById(
      @PathVariable("book-id")
      Integer bookId // URL'den book-id path variable alınır
  ) {
    // BookService.findById() çağrılır ve kitap döner
    return ResponseEntity.ok(service.findById(bookId));
  }
}