package com.degerli.security.book;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * BookRepository - Kitap Veritabanı Erişim Katmanı
 *
 * <p><b>NE:</b> Book entity'si için veritabanı işlemlerini sağlayan Spring Data JPA
 * repository.
 * Sadece JpaRepository'den extend eder, custom method yok.</p>
 *
 * <p><b>NEDEN:</b>
 * - Demo amaçlı basit bir CRUD örneği göstermek için
 * - JPA Auditing özelliğini test etmek için (createdBy, lastModifiedBy)
 * - Spring Security ile korunan bir endpoint örneği için
 * </p>
 *
 * <p><b>NASIL ÇALIŞIR:</b>
 * 1. JpaRepository'den tüm CRUD methodları otomatik gelir
 * 2. BookService bu repository'yi kullanarak kitap kaydetme/listeleme yapar
 * 3. BookController authenticated user'lar için açık
 * </p>
 *
 * <p><b>MEVCUT METHODLAR (JpaRepository'den):</b>
 * - save(Book book): Kitap kaydetme/güncelleme
 * - findAll(): Tüm kitapları listeleme
 * - findById(Integer id): ID ile kitap bulma
 * - delete(Book book): Kitap silme
 * - count(): Toplam kitap sayısı
 * </p>
 *
 * <p><b>KULLANIM ÖRNEĞİ:</b>
 * <pre>
 * // Yeni kitap kaydetme
 * Book book = Book.builder()
 *     .author("Orhan Pamuk")
 *     .isbn("978-0307386908")
 *     .build();
 * bookRepository.save(book);
 *
 * // Tüm kitapları listeleme
 * List&lt;Book&gt; books = bookRepository.findAll();
 * </pre>
 * </p>
 *
 * <p><b>JPA AUDITING:</b>
 * Book entity'sinde @EntityListeners(AuditingEntityListener.class) var.
 * Bu sayede:
 * - createdBy: Kitabı oluşturan user ID otomatik set edilir
 * - createdDate: Oluşturulma tarihi otomatik set edilir
 * - lastModifiedBy: Son güncelleyen user ID otomatik set edilir
 * - lastModifiedDate: Son güncelleme tarihi otomatik set edilir
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - findByAuthor(String author): Yazara göre kitap arama
 * - findByIsbn(String isbn): ISBN ile kitap bulma
 * - Pagination desteği ekle (findAll(Pageable pageable))
 * - Search özelliği ekle (author veya ISBN'de arama)
 * </p>
 *
 * <p><b>NOT:</b>
 * Bu repository demo amaçlı. Gerçek bir projede daha fazla custom method olurdu.
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see Book Kitap entity'si
 * @see JpaRepository Spring Data JPA'nın base repository interface'i
 * @see com.degerli.security.book.BookService Bu repository'yi kullanan service
 */
public interface BookRepository extends JpaRepository<Book, Integer> {
  // Custom method yok, sadece JpaRepository'den gelen methodlar kullanılıyor

  // TODO: Gelecekte eklenebilecek custom methodlar:
  // Optional<Book> findByIsbn(String isbn);
  // List<Book> findByAuthorContainingIgnoreCase(String author);
  // Page<Book> findAll(Pageable pageable);
}