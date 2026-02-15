
# Flow Ozet
   
**UserDetailsService** kullanıcıyı DB'den getirir.

**DaoAuthenticationProvider** bunu ve password check kullanarak login sırasında authenticate yapar.

**AuthenticationConfiguration** (Spring Security'nin otomatik oluşturduğu), context'teki tüm provider'ları bulur ve **AuthenticationManager** oluşturur.

**authManager.authenticate()** provider'ın authenticate methodunu çağırır, o da user ve password check yapar (DaoAuthenticationProvider).

Bunların ilişkisi **ApplicationConfig**'te kurulur: Bean'leri tanımlayıp birbirine bağlarız.

---

## 📊 Görsel Özet:

```
ApplicationConfig (Bizim yazdığımız)
├── UserDetailsService bean → DB'den user getir
├── PasswordEncoder bean → Şifre hash/check
├── DaoAuthenticationProvider bean → Yukarıdaki 2'sini kullan
└── AuthenticationManager bean → config.getAuthenticationManager() ile AL
    
AuthenticationConfiguration (Spring'in otomatik oluşturduğu)
└── getAuthenticationManager()
    ├── Context'te DaoAuthenticationProvider'ı BUL
    ├── ProviderManager OLUŞTUR
    └── Provider'ı içine EKLE

Login sırasında:
authManager.authenticate()
└── DaoAuthenticationProvider.authenticate()
    ├── UserDetailsService.loadUserByUsername()
    └── PasswordEncoder.matches()
```

---

## 1️⃣ LOGIN Flow (AuthenticationManager kullanır)

```java
// AuthenticationService.java
public AuthenticationResponse authenticate(AuthenticationRequest request) {
    
    // ✅ AuthenticationManager kullanılıyor!
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
        )
    );
    // ├── DaoAuthenticationProvider.authenticate()
    // │   ├── UserDetailsService.loadUserByUsername()
    // │   └── PasswordEncoder.matches()
    
    // Kullanıcı doğrulandı, JWT oluştur
    var user = repository.findByEmail(request.getEmail()).orElseThrow();
    var jwtToken = jwtService.generateToken(user);
    return AuthenticationResponse.builder().accessToken(jwtToken).build();
}
```

**Özet:**
- ✅ **AuthenticationManager** kullanılır
- ✅ **DaoAuthenticationProvider** şifre kontrolü yapar
- ✅ **UserDetailsService** otomatik çağrılır
- ✅ Spring Security'nin tüm doğrulama mekanizması devrede

---

## 2️⃣ REGISTER Flow (AuthenticationManager KULLANILMAZ!)

```java
// AuthenticationService.java
public AuthenticationResponse register(RegisterRequest request) {
    
    // ❌ AuthenticationManager YOK!
    // ❌ DaoAuthenticationProvider YOK!
    // ❌ UserDetailsService YOK!
    
    // Manuel olarak user oluştur
    var user = User.builder()
        .firstname(request.getFirstname())
        .lastname(request.getLastname())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword())) // ⬅️ Sadece encoder
        .role(request.getRole())
        .build();
    
    // DB'ye kaydet
    var savedUser = repository.save(user);
    
    // JWT oluştur
    var jwtToken = jwtService.generateToken(user);
    return AuthenticationResponse.builder().accessToken(jwtToken).build();
}
```

**Özet:**
- ❌ **AuthenticationManager** kullanılmaz
- ❌ **DaoAuthenticationProvider** kullanılmaz
- ❌ **UserDetailsService** kullanılmaz
- ✅ Sadece **PasswordEncoder** kullanılır (şifre hash'lemek için)
- ✅ Manuel olarak user oluşturulur ve DB'ye kaydedilir

---

## 3️⃣ Normal Servis Endpoint'leri (JWT Filter devrede)

```java
// BookController.java
@RestController
@RequestMapping("/api/v1/books")
public class BookController {
    
    @GetMapping
    public ResponseEntity<List<Book>> findAllBooks() {
        // ❌ AuthenticationManager YOK!
        // ❌ DaoAuthenticationProvider YOK!
        // ❌ UserDetailsService YOK!
        
        // Sadece business logic
        return ResponseEntity.ok(service.findAll());
    }
}
```

**Ama arka planda ne oluyor?**

```
1️⃣ Request geliyor: GET /api/v1/books
   Header: Authorization: Bearer <JWT_TOKEN>

2️⃣ JwtAuthenticationFilter devreye giriyor
   ├── JWT token'ı extract et
   ├── Token geçerli mi? (jwtService.isTokenValid())
   ├── UserDetailsService.loadUserByUsername() ⬅️ BURADA KULLANILIYOR!
   │   └── User user = repository.findByEmail(email)
   ├── UsernamePasswordAuthenticationToken oluştur
   └── SecurityContextHolder.getContext().setAuthentication(authToken)

3️⃣ AuthorizationFilter devreye giriyor
   ├── SecurityContext'ten Authentication al
   ├── User'ın role'ü var mı? (ADMIN, USER, etc.)
   └── Endpoint'e erişim izni var mı?

4️⃣ Controller method'u çalışıyor
   └── Business logic
```

**Özet:**
- ❌ **AuthenticationManager** kullanılmaz
- ❌ **DaoAuthenticationProvider** kullanılmaz
- ✅ **UserDetailsService** kullanılır (JwtAuthenticationFilter içinde)
- ✅ **JwtService** token doğrulama yapar
- ✅ **SecurityContext** kullanıcı bilgisini tutar

---

## 📊 Karşılaştırma Tablosu

| Bileşen | LOGIN | REGISTER | Normal Endpoint |
|---------|-------|----------|-----------------|
| **AuthenticationManager** | ✅ Kullanılır | ❌ Kullanılmaz | ❌ Kullanılmaz |
| **DaoAuthenticationProvider** | ✅ Kullanılır | ❌ Kullanılmaz | ❌ Kullanılmaz |
| **UserDetailsService** | ✅ Kullanılır (otomatik) | ❌ Kullanılmaz | ✅ Kullanılır (JwtFilter'da) |
| **PasswordEncoder** | ✅ Kullanılır (check) | ✅ Kullanılır (encode) | ❌ Kullanılmaz |
| **JwtService** | ✅ Token oluşturur | ✅ Token oluşturur | ✅ Token doğrular |
| **SecurityContext** | ❌ Set edilmez | ❌ Set edilmez | ✅ Set edilir |

---

## 🎯 Neden Farklı?

### LOGIN:
- Kullanıcı **henüz doğrulanmadı**
- **Şifre kontrolü** gerekli
- Spring Security'nin **tam doğrulama mekanizması** kullanılır

### REGISTER:
- Yeni kullanıcı **oluşturuluyor**
- Şifre kontrolü yok, sadece **hash'leme** var
- Spring Security'nin doğrulama mekanizması **gereksiz**

### Normal Endpoint:
- Kullanıcı **zaten doğrulandı** (JWT var)
- Sadece **token geçerliliği** kontrol edilir
- **SecurityContext**'e user bilgisi set edilir

---

## 🔍 UserDetailsService'in İki Farklı Kullanımı

### 1️⃣ Login sırasında (DaoAuthenticationProvider içinde):
```java
authenticationManager.authenticate()
└── DaoAuthenticationProvider.authenticate()
    └── UserDetailsService.loadUserByUsername() ⬅️ Şifre kontrolü için
```

### 2️⃣ Normal endpoint'lerde (JwtAuthenticationFilter içinde):
```java
JwtAuthenticationFilter.doFilterInternal()
└── UserDetailsService.loadUserByUsername() ⬅️ JWT'den user bilgisi almak için
```

---


# Filter Chain acisindan 3 case nasil?

## 🔗 Spring Security Filter Chain (Hatırlatma)

```
Request → Filter Chain → Controller
          │
          ├── SecurityContextHolderFilter
          ├── CorsFilter
          ├── CsrfFilter
          ├── LogoutFilter
          ├── JwtAuthenticationFilter ⬅️ Bizim custom filter
          ├── AuthorizationFilter
          └── ExceptionTranslationFilter
```

---

## 1️⃣ LOGIN Flow (Filter Chain'den GEÇİYOR ama farklı)

### Request:
```http
POST /api/v1/auth/authenticate
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

### Filter Chain Akışı:

```
1️⃣ SecurityContextHolderFilter
   └── SecurityContext oluştur (boş)

2️⃣ CorsFilter
   └── CORS kontrolü (geçer)

3️⃣ CsrfFilter
   └── CSRF token kontrolü (disabled olduğu için geçer)

4️⃣ LogoutFilter
   └── Logout endpoint'i mi? ❌ Hayır, geç

5️⃣ JwtAuthenticationFilter ⬅️ ÖNEMLİ!
   └── JWT token var mı?
       └── Authorization header var mı? ❌ HAYIR!
       └── Filter chain'e devam et (hiçbir şey yapma)

6️⃣ AuthorizationFilter
   └── /api/v1/auth/** permitAll() ✅ İzin var!
   └── SecurityContext'te user var mı? ❌ Yok ama sorun değil

7️⃣ Controller'a ulaş
   └── AuthenticationController.authenticate()
       └── AuthenticationService.authenticate()
           └── authenticationManager.authenticate() ⬅️ BURADA doğrulama
```

**Özet:**
- ✅ Filter chain **tamamen geçiliyor**
- ✅ JwtAuthenticationFilter **hiçbir şey yapmıyor** (JWT yok çünkü)
- ✅ AuthorizationFilter **permitAll()** olduğu için geçiyor
- ✅ Controller'da **AuthenticationManager** devreye giriyor

---

## 2️⃣ REGISTER Flow (Filter Chain'den GEÇİYOR, hiçbir şey olmuyor)

### Request:
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "firstname": "John",
  "lastname": "Doe",
  "email": "john@example.com",
  "password": "password123",
  "role": "USER"
}
```

### Filter Chain Akışı:

```
1️⃣ SecurityContextHolderFilter
   └── SecurityContext oluştur (boş)

2️⃣ CorsFilter
   └── CORS kontrolü (geçer)

3️⃣ CsrfFilter
   └── CSRF token kontrolü (disabled, geçer)

4️⃣ LogoutFilter
   └── Logout endpoint'i mi? ❌ Hayır, geç

5️⃣ JwtAuthenticationFilter ⬅️ ÖNEMLİ!
   └── JWT token var mı?
       └── Authorization header var mı? ❌ HAYIR!
       └── Filter chain'e devam et (hiçbir şey yapma)

6️⃣ AuthorizationFilter
   └── /api/v1/auth/** permitAll() ✅ İzin var!
   └── SecurityContext'te user var mı? ❌ Yok ama sorun değil

7️⃣ Controller'a ulaş
   └── AuthenticationController.register()
       └── AuthenticationService.register()
           └── Manuel user oluştur ve kaydet
```

**Özet:**
- ✅ Filter chain **tamamen geçiliyor**
- ✅ JwtAuthenticationFilter **hiçbir şey yapmıyor** (JWT yok çünkü)
- ✅ AuthorizationFilter **permitAll()** olduğu için geçiyor
- ✅ Controller'da **manuel user oluşturma**

---

## 3️⃣ Normal Endpoint Flow (Filter Chain FULL ÇALIŞIYOR!)

### Request:
```http
GET /api/v1/books
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Filter Chain Akışı:

```
1️⃣ SecurityContextHolderFilter
   └── SecurityContext oluştur (boş)

2️⃣ CorsFilter
   └── CORS kontrolü (geçer)

3️⃣ CsrfFilter
   └── CSRF token kontrolü (disabled, geçer)

4️⃣ LogoutFilter
   └── Logout endpoint'i mi? ❌ Hayır, geç

5️⃣ JwtAuthenticationFilter ⬅️ BURADA İŞ OLUYOR!
   │
   ├── Authorization header var mı? ✅ VAR!
   │   └── "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   │
   ├── JWT token'ı extract et
   │   └── jwtService.extractUsername(jwt)
   │       └── email = "user@example.com"
   │
   ├── SecurityContext'te user var mı? ❌ YOK
   │
   ├── UserDetailsService.loadUserByUsername("user@example.com")
   │   └── User user = repository.findByEmail("user@example.com")
   │
   ├── Token geçerli mi?
   │   └── jwtService.isTokenValid(jwt, userDetails)
   │       ├── Token expire olmamış mı? ✅
   │       ├── Token'daki email == user.email? ✅
   │       └── Token revoke edilmemiş mi? ✅
   │
   ├── UsernamePasswordAuthenticationToken oluştur
   │   └── authToken = new UsernamePasswordAuthenticationToken(
   │           userDetails, 
   │           null, 
   │           userDetails.getAuthorities()
   │       )
   │
   └── SecurityContext'e set et
       └── SecurityContextHolder.getContext().setAuthentication(authToken)

6️⃣ AuthorizationFilter ⬅️ BURADA YETKİ KONTROLÜ!
   │
   ├── SecurityContext'ten Authentication al
   │   └── Authentication auth = SecurityContextHolder.getContext().getAuthentication()
   │
   ├── User authenticated mi? ✅ EVET
   │
   ├── Endpoint için gerekli role var mı?
   │   └── @PreAuthorize("hasRole('USER')") veya @PreAuthorize("hasAuthority('book:read')")
   │   └── User'ın role'ü: USER ✅
   │   └── User'ın permission'ı: book:read ✅
   │
   └── İzin var! Devam et

7️⃣ Controller'a ulaş
   └── BookController.findAllBooks()
       └── service.findAll()
```

**Özet:**
- ✅ Filter chain **tamamen çalışıyor**
- ✅ JwtAuthenticationFilter **JWT doğrulama yapıyor**
- ✅ UserDetailsService **user bilgisini getiriyor**
- ✅ SecurityContext'e **user set ediliyor**
- ✅ AuthorizationFilter **role/permission kontrolü yapıyor**

---

## 📊 Filter Chain Karşılaştırması

| Filter | LOGIN | REGISTER | Normal Endpoint |
|--------|-------|----------|-----------------|
| **SecurityContextHolderFilter** | ✅ Boş context | ✅ Boş context | ✅ Boş context |
| **CorsFilter** | ✅ Geçer | ✅ Geçer | ✅ Geçer |
| **CsrfFilter** | ✅ Disabled | ✅ Disabled | ✅ Disabled |
| **LogoutFilter** | ✅ Skip | ✅ Skip | ✅ Skip |
| **JwtAuthenticationFilter** | ⚠️ JWT yok, skip | ⚠️ JWT yok, skip | ✅ **JWT doğrula, user set et** |
| **AuthorizationFilter** | ✅ permitAll() | ✅ permitAll() | ✅ **Role/permission kontrol** |
| **Controller** | ✅ AuthManager kullan | ✅ Manuel kayıt | ✅ Business logic |

---

## 🎯 SecurityContext Durumu

### LOGIN sonrası:
```java
SecurityContextHolder.getContext().getAuthentication() 
// → null (SecurityContext'e hiçbir şey set edilmedi)
```

### REGISTER sonrası:
```java
SecurityContextHolder.getContext().getAuthentication() 
// → null (SecurityContext'e hiçbir şey set edilmedi)
```

### Normal Endpoint sırasında:
```java
SecurityContextHolder.getContext().getAuthentication() 
// → UsernamePasswordAuthenticationToken
//    ├── Principal: UserDetails (user bilgisi)
//    ├── Credentials: null
//    └── Authorities: [ROLE_USER, book:read, book:write, ...]
```

---

## 🔍 Kritik Fark: JwtAuthenticationFilter

### LOGIN/REGISTER:
```java
// JwtAuthenticationFilter.java
protected void doFilterInternal(HttpServletRequest request, ...) {
    final String authHeader = request.getHeader("Authorization");
    
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        filterChain.doFilter(request, response); // ⬅️ Hiçbir şey yapma, geç!
        return;
    }
    
    // Buraya hiç gelmez çünkü JWT yok
}
```

### Normal Endpoint:
```java
// JwtAuthenticationFilter.java
protected void doFilterInternal(HttpServletRequest request, ...) {
    final String authHeader = request.getHeader("Authorization");
    
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        filterChain.doFilter(request, response);
        return;
    }
    
    // ✅ JWT var! Devam et
    final String jwt = authHeader.substring(7);
    final String userEmail = jwtService.extractUsername(jwt);
    
    // UserDetailsService kullan
    UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
    
    // Token geçerli mi?
    if (jwtService.isTokenValid(jwt, userDetails)) {
        // SecurityContext'e set et
        UsernamePasswordAuthenticationToken authToken = 
            new UsernamePasswordAuthenticationToken(
                userDetails, 
                null, 
                userDetails.getAuthorities()
            );
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
    
    filterChain.doFilter(request, response);
}
```

---

## 🎬 Özet

### 1️⃣ LOGIN:
- Filter chain geçiliyor ama **JwtAuthenticationFilter skip**
- Controller'da **AuthenticationManager** devreye giriyor
- SecurityContext **boş kalıyor**

### 2️⃣ REGISTER:
- Filter chain geçiliyor ama **JwtAuthenticationFilter skip**
- Controller'da **manuel user oluşturma**
- SecurityContext **boş kalıyor**

### 3️⃣ Normal Endpoint:
- Filter chain **tam çalışıyor**
- **JwtAuthenticationFilter** JWT doğrulama yapıyor
- **UserDetailsService** user getiriyor
- **SecurityContext'e user set ediliyor**
- **AuthorizationFilter** role/permission kontrolü yapıyor

---
