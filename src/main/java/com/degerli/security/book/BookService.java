package com.degerli.security.book;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * BookService - Kitap İşlemleri Servisi
 *
 * <p><b>NE:</b> Kitap ile ilgili business logic işlemlerini yöneten servis.
 * CRUD operasyonları (Create, Read, Update, Delete) sağlar.</p>
 *
 * <p><b>NEDEN:</b>
 * - Business logic'i controller'dan ayırmak (separation of concerns)
 * - Kitap işlemlerini merkezi bir yerden yönetmek
 * - Repository katmanı ile controller arasında köprü oluşturmak
 * - İleride eklenmesi muhtemel business rule'ları buraya eklemek
 * </p>
 *
 * <p><b>NASIL ÇALIŞIR:</b>
 * Controller -> Service -> Repository -> Database
 * <p>
 * 1. Controller request alır
 * 2. Service business logic uygular
 * 3. Repository DB işlemlerini yapar
 * 4. Sonuç controller'a döner
 * </p>
 *
 * <p><b>MEVCUT ÖZELLİKLER:</b>
 * - Kitap kaydetme (save)
 * - Tüm kitapları listeleme (findAll)
 * - ID ile kitap bulma (findById)
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Pagination ekle (findAll için PageRequest)
 * - Filtering ekle (author, genre, vb. ile arama)
 * - Sorting ekle (name, author, createdDate, vb.)
 * - Validation ekle (kitap zaten var mı, vb.)
 * - Exception handling ekle (custom exception'lar)
 * - DTO kullan (Book entity'sini direkt dönme)
 * - Update ve Delete operasyonları ekle
 * - Audit logging ekle (kim ne zaman kitap ekledi)
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see BookController Kitap endpoint'leri
 * @see BookRepository Kitap DB işlemleri
 * @see Book Kitap entity'si
 */
@Service
@RequiredArgsConstructor // Lombok: final field için constructor
public class BookService {

  /**
   * Kitap repository'si
   *
   * <p>Kitap DB işlemleri için kullanılır (CRUD operasyonları).</p>
   */
  private final BookRepository repository;

  /**
   * Yeni kitap kaydeder
   *
   * <p><b>NE:</b> BookRequest'ten Book entity oluşturur ve DB'ye kaydeder.</p>
   *
   * <p><b>AKIŞ:</b>
   * 1. BookRequest alınır (author, isbn)
   * 2. Book entity oluşturulur
   * 3. Repository.save() ile DB'ye kaydedilir
   * 4. Kaydedilen Book döner
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * BookRequest request = BookRequest.builder()
   *     .author("Gokhan Degerli")
   *     .isbn("978-3-16-148410-0")
   *     .build();
   *
   * Book savedBook = bookService.save(request);
   * // savedBook.id = 1
   * // savedBook.author = "Gokhan Degerli"
   * // savedBook.isbn = "978-3-16-148410-0"
   * </pre>
   * </p>
   *
   * <p><b>TODO:</b>
   * - ISBN validation ekle (format kontrolü)
   * - Duplicate kontrolü ekle (aynı ISBN ile iki kitap olmasın)
   * - Author validation ekle (boş olmasın)
   * - DTO kullan (Book entity'sini direkt dönme)
   * - Exception handling ekle (DataIntegrityViolationException, vb.)
   * </p>
   *
   * <p><b>KULLANIM YERİ:</b>
   * - BookController.save(): POST /api/v1/books
   * </p>
   *
   * @param request Kitap bilgileri (author, isbn)
   * @return Kaydedilen kitap entity'si
   * @see BookRequest Kitap request DTO'su
   * @see Book Kitap entity'si
   */
  public Book save(BookRequest request) {
    // 1. BookRequest'ten Book entity oluştur
    var book = Book.builder().author(request.getAuthor()) // Yazar
        .isbn(request.getIsbn())     // ISBN numarası
        .build();

    // 2. Book'u DB'ye kaydet ve döner
    return repository.save(book);
  }

  /**
   * Tüm kitapları listeler
   *
   * <p><b>NE:</b> DB'deki tüm kitapları liste olarak döner.</p>
   *
   * <p><b>AKIŞ:</b>
   * 1. Repository.findAll() çağrılır
   * 2. Tüm kitaplar liste olarak döner
   * </p>
   *
   * <p><b>PERFORMANS UYARISI:</b>
   * findAll() tüm kayıtları getirir. DB'de çok fazla kitap varsa performans sorunu olabilir.
   * Pagination kullanılması önerilir.
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * List<Book> books = bookService.findAll();
   * // books = [Book(id=1, author="Gokhan", isbn="123"), Book(id=2, ...)]
   * </pre>
   * </p>
   *
   * <p><b>TODO:</b>
   * - Pagination ekle (Page<Book> findAll(Pageable pageable))
   * - Filtering ekle (author, isbn, vb. ile arama)
   * - Sorting ekle (author, createdDate, vb.)
   * - DTO kullan (Book entity'sini direkt dönme)
   * - Cache ekle (Redis ile cache'leme)
   * </p>
   *
   * <p><b>KULLANIM YERİ:</b>
   * - BookController.findAllBooks(): GET /api/v1/books
   * </p>
   *
   * @return Tüm kitapların listesi
   * @see Book Kitap entity'si
   */
  public List<Book> findAll() {
    // Repository'den tüm kitapları getir ve döner
    return repository.findAll();
  }

  /**
   * ID ile kitap bulur
   *
   * <p><b>NE:</b> Verilen ID'ye sahip kitabı DB'den bulur ve döner.</p>
   *
   * <p><b>AKIŞ:</b>
   * 1. Repository.findById(id) çağrılır
   * 2. Kitap bulunursa döner
   * 3. Bulunamazsa exception fırlatır (orElseThrow)
   * </p>
   *
   * <p><b>KULLANIM ÖRNEĞİ:</b>
   * <pre>
   * Book book = bookService.findById(1);
   * // book = Book(id=1, author="Gokhan", isbn="123")
   *
   * Book notFound = bookService.findById(999);
   * // NoSuchElementException fırlatır
   * </pre>
   * </p>
   *
   * <p><b>EXCEPTION:</b>
   * - NoSuchElementException: Kitap bulunamazsa fırlatılır
   * </p>
   *
   * <p><b>TODO:</b>
   * - Custom exception ekle (BookNotFoundException)
   * - DTO kullan (Book entity'sini direkt dönme)
   * - Cache ekle (Redis ile cache'leme)
   * </p>
   *
   * <p><b>KULLANIM YERİ:</b>
   * - BookController.findById(): GET /api/v1/books/{book-id}
   * </p>
   *
   * @param id Kitap ID'si
   * @return Bulunan kitap entity'si
   * @throws java.util.NoSuchElementException Kitap bulunamazsa
   * @see Book Kitap entity'si
   */
  public Book findById(Integer id) {
    // Repository'den ID ile kitap bul
    // Bulunamazsa NoSuchElementException fırlat
    return repository.findById(id).orElseThrow(); // Kitap bulunamazsa exception fırlat
  }
}