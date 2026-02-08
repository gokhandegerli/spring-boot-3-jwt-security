# 🔐 Spring Boot 3.0 Security with JWT Implementation

Bu proje, **Spring Boot 3.0** ve **JSON Web Tokens (JWT)** kullanarak modern, stateless authentication ve authorization sisteminin nasıl implement edileceğini gösterir.

---

## 📋 İçindekiler

1. [Özellikler](#-özellikler)
2. [Teknolojiler](#-teknolojiler)
3. [Kurulum](#-kurulum)
4. [Spring Security Felsefesi](#-spring-security-felsefesi)
5. [JWT Authentication Flow](#-jwt-authentication-flow)
6. [Proje Mimarisi](#-proje-mimarisi)
7. [Projeyi Nasıl Okumak Gerekir?](#-projeyi-nasıl-okumak-gerekir)
8. [API Endpoints](#-api-endpoints)
9. [Örnek Kullanım](#-örnek-kullanım)
10. [Güvenlik Notları](#-güvenlik-notları)
11. [TODO İyileştirmeler](#-todo-iyileştirmeler)
12. [Kaynaklar](#-kaynaklar)

---

## ✨ Özellikler

- ✅ **User Registration & Login** - JWT authentication ile kullanıcı kaydı ve girişi
- ✅ **Password Encryption** - BCrypt ile şifre hashleme
- ✅ **Role-Based Authorization** - Spring Security ile rol bazlı yetkilendirme
- ✅ **Permission-Based Authorization** - Granular permission kontrolü
- ✅ **JWT Access Token** - Stateless authentication için JWT token
- ✅ **JWT Refresh Token** - Access token yenilemek için refresh token
- ✅ **Token Revocation** - Logout ile token iptal etme
- ✅ **Granular Token Management** - ACCESS ve REFRESH token'ları ayrı ayrı yönetme
- ✅ **Custom Access Denied Handling** - Özelleştirilmiş 403 Forbidden response
- ✅ **Swagger/OpenAPI Documentation** - API dokümantasyonu

---

## 🛠 Teknolojiler

| Teknoloji | Versiyon | Açıklama |
|-----------|----------|----------|
| **Java** | 17+ | Modern Java features (Records, Text Blocks, vb.) |
| **Spring Boot** | 3.0+ | Framework |
| **Spring Security** | 6.0+ | Authentication & Authorization |
| **Spring Data JPA** | 3.0+ | Database ORM |
| **PostgreSQL** | 14+ | Relational database |
| **JJWT** | 0.11.5 | JWT token generation & validation |
| **BCrypt** | - | Password hashing algorithm |
| **Lombok** | 1.18.26 | Boilerplate code reduction |
| **SpringDoc OpenAPI** | 2.0.2 | Swagger UI |
| **Maven** | 3+ | Build tool |

---

## 🚀 Kurulum

### **Gereksinimler**
- JDK 17+
- Maven 3+
- PostgreSQL 14+

### **Adımlar**

1. **Projeyi klonla:**
   ```bash
   git clone https://github.com/gokhandegerli/spring-boot-3-jwt-security.git
   cd spring-boot-3-jwt-security
   ```

2. **PostgreSQL database oluştur:**
   ```sql
   CREATE DATABASE jwt_security;
   ```

3. **application.yml dosyasını düzenle:**
   ```yaml
   spring:
     datasource:
       url: jdbc:postgresql://localhost:5432/jwt_security
       username: your_username
       password: your_password
   ```

4. **Projeyi build et:**
   ```bash
   mvn clean install
   ```

5. **Projeyi çalıştır:**
   ```bash
   mvn spring-boot:run
   ```

6. **Uygulamaya eriş:**
   - API: http://localhost:8080
   - Swagger UI: http://localhost:8080/swagger-ui.html

---

## 🧠 Spring Security Felsefesi

### **1. Authentication vs Authorization**

| Kavram | Açıklama | Örnek |
|--------|----------|-------|
| **Authentication** | "Sen kimsin?" sorusuna cevap | Login (email + password) |
| **Authorization** | "Ne yapma yetkin var?" sorusuna cevap | Admin paneline erişim |

### **2. Spring Security Filter Chain**

Spring Security, **Filter Chain** pattern'i kullanır. Her HTTP request, bir dizi filter'dan geçer:

```
HTTP Request
    ↓
1. SecurityContextPersistenceFilter (SecurityContext yükle)
    ↓
2. JwtAuthenticationFilter (JWT token validate et) ← BU PROJEDEKİ CUSTOM FILTER
    ↓
3. UsernamePasswordAuthenticationFilter (username/password authentication)
    ↓
4. ExceptionTranslationFilter (exception handling)
    ↓
5. FilterSecurityInterceptor (authorization - role/permission kontrolü)
    ↓
Controller Method
    ↓
HTTP Response
```

### **3. SecurityContext**

**SecurityContext**, Spring Security'nin **thread-local storage**'ıdır. Her thread için ayrı bir SecurityContext tutar.

```java
// SecurityContext'e Authentication set et
SecurityContextHolder.getContext().setAuthentication(authToken);

// SecurityContext'ten Authentication al
Authentication auth = SecurityContextHolder.getContext().getAuthentication();

// Current user'ı al
User user = (User) auth.getPrincipal();
```

### **4. Stateless Authentication**

**Stateful (Session-based):**
- Server'da session tutar (memory/database)
- Her request'te session ID gönderilir
- Scalability sorunu (load balancer, multiple server)

**Stateless (JWT-based):**
- Server'da session tutmaz
- Her request'te JWT token gönderilir
- Token içinde user bilgisi var (self-contained)
- Scalability kolay (horizontal scaling)

---

## 🔄 JWT Authentication Flow

### **1. Registration Flow**

```
Client                          Server
  |                               |
  |  POST /api/v1/auth/register   |
  |  { email, password, ... }     |
  |------------------------------>|
  |                               |
  |                               | 1. Password'ü BCrypt ile hashle
  |                               | 2. User'ı DB'ye kaydet
  |                               | 3. JWT access token oluştur (ACCESS purpose)
  |                               | 4. JWT refresh token oluştur (REFRESH purpose)
  |                               | 5. Token'ları DB'ye kaydet (ayrı ayrı)
  |                               |
  |  { access_token, refresh_token }
  |<------------------------------|
  |                               |
```

### **2. Login Flow**

```
Client                          Server
  |                               |
  |  POST /api/v1/auth/authenticate |
  |  { email, password }          |
  |------------------------------>|
  |                               |
  |                               | 1. User'ı DB'den bul (email)
  |                               | 2. Password'ü BCrypt ile kontrol et
  |                               | 3. AuthenticationManager.authenticate()
  |                               | 4. JWT access token oluştur (ACCESS purpose)
  |                               | 5. JWT refresh token oluştur (REFRESH purpose)
  |                               | 6. Eski TÜM token'ları revoke et (ACCESS + REFRESH)
  |                               | 7. Yeni token'ları DB'ye kaydet (ayrı ayrı)
  |                               |
  |  { access_token, refresh_token }
  |<------------------------------|
  |                               |
```

### **3. Authenticated Request Flow**

```
Client                          Server
  |                               |
  |  GET /api/v1/books            |
  |  Authorization: Bearer <JWT>  |
  |------------------------------>|
  |                               |
  |                               | JwtAuthenticationFilter:
  |                               | 1. Authorization header'dan JWT al
  |                               | 2. JWT'den username (email) çıkar
  |                               | 3. User'ı DB'den yükle
  |                               | 4. Token'ı validate et:
  |                               |    - Signature valid mi?
  |                               |    - Expired değil mi?
  |                               |    - Revoked değil mi?
  |                               |    - TokenPurpose ACCESS mi?
  |                               | 5. SecurityContext'e Authentication set et
  |                               |
  |                               | FilterSecurityInterceptor:
  |                               | 6. Role/Permission kontrolü yap
  |                               | 7. Controller method'u çağır
  |                               |
  |  [ { book1 }, { book2 }, ... ] |
  |<------------------------------|
  |                               |
```

### **4. Refresh Token Flow**

```
Client                          Server
  |                               |
  |  POST /api/v1/auth/refresh-token |
  |  Authorization: Bearer <REFRESH_TOKEN> |
  |------------------------------>|
  |                               |
  |                               | 1. Refresh token'ı validate et
  |                               | 2. TokenPurpose REFRESH mi kontrol et
  |                               | 3. User'ı DB'den yükle
  |                               | 4. Yeni access token oluştur (ACCESS purpose)
  |                               | 5. Sadece eski ACCESS token'ları revoke et
  |                               |    (REFRESH token korunur!)
  |                               | 6. Yeni access token'ı DB'ye kaydet
  |                               |
  |  { access_token, refresh_token }
  |  (refresh_token aynı kalır)   |
  |<------------------------------|
  |                               |
```

### **5. Logout Flow**

```
Client                          Server
  |                               |
  |  POST /api/v1/auth/logout     |
  |  Authorization: Bearer <JWT>  |
  |------------------------------>|
  |                               |
  |                               | LogoutService:
  |                               | 1. JWT token'ı DB'de bul
  |                               | 2. User'ın TÜM token'larını bul
  |                               | 3. TÜM token'ları revoke et (ACCESS + REFRESH)
  |                               | 4. SecurityContext'i temizle
  |                               |
  |  200 OK                       |
  |<------------------------------|
  |                               |
```

---

## 🏗 Proje Mimarisi

### **Layered Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                     PRESENTATION LAYER                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Auth         │  │ User         │  │ Book         │      │
│  │ Controller   │  │ Controller   │  │ Controller   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                       SERVICE LAYER                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Auth         │  │ User         │  │ Book         │      │
│  │ Service      │  │ Service      │  │ Service      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐                         │
│  │ JWT          │  │ Logout       │                         │
│  │ Service      │  │ Service      │                         │
│  └──────────────┘  └──────────────┘                         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                     REPOSITORY LAYER                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ User         │  │ Token        │  │ Book         │      │
│  │ Repository   │  │ Repository   │  │ Repository   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                       DOMAIN LAYER                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ User         │  │ Token        │  │ Book         │      │
│  │ Entity       │  │ Entity       │  │ Entity       │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Role         │  │ Permission   │  │ TokenType    │      │
│  │ Enum         │  │ Enum         │  │ Enum         │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
│  ┌──────────────┐                                            │
│  │ TokenPurpose │                                            │
│  │ Enum         │                                            │
│  └──────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                         DATABASE                             │
│                       PostgreSQL                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    SECURITY/CONFIG LAYER                     │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ SecurityConfiguration                                 │   │
│  │ - Filter chain configuration                          │   │
│  │ - URL authorization rules                             │   │
│  │ - CORS configuration                                  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ JwtAuthenticationFilter                               │   │
│  │ - JWT token validation                                │   │
│  │ - SecurityContext population                          │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ ApplicationConfig                                     │   │
│  │ - UserDetailsService bean                             │   │
│  │ - AuthenticationProvider bean                         │   │
│  │ - PasswordEncoder bean                                │   │
│  │ - AuthenticationManager bean                          │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### **Package Structure**

```
com.degerli.security
├── config/                          # Security & Application Configuration
│   ├── ApplicationConfig.java       # Bean definitions (UserDetailsService, AuthenticationProvider, vb.)
│   ├── JwtAuthenticationFilter.java # JWT token validation filter
│   ├── LogoutService.java           # Logout handler
│   ├── OpenApiConfig.java           # Swagger/OpenAPI configuration
│   ├── SecurityConfiguration.java   # Spring Security configuration
│   └── ApplicationAuditAware.java   # JPA Auditing configuration
│
├── user/                            # User Domain
│   ├── User.java                    # User entity (UserDetails implementation)
│   ├── Role.java                    # Role enum (ADMIN, MANAGER, USER)
│   ├── Permission.java              # Permission enum (granular permissions)
│   ├── UserRepository.java          # User data access
│   ├── UserService.java             # User business logic
│   └── UserController.java          # User REST endpoints
│
├── token/                           # Token Domain
│   ├── Token.java                   # Token entity (JWT token storage)
│   ├── TokenType.java               # Token type enum (BEARER)
│   ├── TokenPurpose.java            # Token purpose enum (ACCESS, REFRESH)
│   └── TokenRepository.java         # Token data access
│
├── auth/                            # Authentication Domain
│   ├── AuthenticationService.java   # Authentication business logic
│   ├── AuthenticationController.java # Auth REST endpoints (register, login, refresh, logout)
│   ├── AuthenticationRequest.java   # Login request DTO
│   ├── AuthenticationResponse.java  # Login response DTO (access_token, refresh_token)
│   └── RegisterRequest.java         # Registration request DTO
│
├── book/                            # Book Domain (Example Resource)
│   ├── Book.java                    # Book entity
│   ├── BookRepository.java          # Book data access
│   ├── BookService.java             # Book business logic
│   ├── BookController.java          # Book REST endpoints
│   └── BookRequest.java             # Book request DTO
│
├── demo/                            # Demo Controllers (Testing Authorization)
│   ├── DemoController.java          # Public demo endpoint
│   ├── AdminController.java         # Admin-only endpoints
│   └── ManagementController.java    # Manager-only endpoints
│
└── SecurityApplication.java         # Spring Boot main class
```

---

## 📖 Projeyi Nasıl Okumak Gerekir?

### **🎯 Öğrenme Yol Haritası**

Projeyi anlamak için **aşağıdaki sırayı** takip etmenizi öneririm:

---

### **ADIM 1: Domain Layer'ı Anla (Veri Modeli)**

**Okuma Sırası:**
1. `User.java` - Kullanıcı entity'si (UserDetails implementation)
2. `Role.java` - Rol enum'u (ADMIN, MANAGER, USER)
3. `Permission.java` - Permission enum'u (granular permissions)
4. `Token.java` - JWT token entity'si
5. `TokenType.java` - Token type enum'u (BEARER)
6. `TokenPurpose.java` - Token purpose enum'u (ACCESS, REFRESH)

**Dikkat Edilmesi Gerekenler:**
- ✅ `User` class'ı `UserDetails` interface'ini implement ediyor (Spring Security requirement)
- ✅ `getAuthorities()` method'u role ve permission'ları `GrantedAuthority` listesine dönüştürüyor
- ✅ `Role` enum'u içinde `permissions` listesi var (role → permissions mapping)
- ✅ `Token` entity'si `user` ile `@ManyToOne` ilişkisi var (bir user'ın birden fazla token'ı olabilir)
- ✅ `TokenType` enum'u token tipini belirliyor (BEARER)
- ✅ `TokenPurpose` enum'u token amacını belirliyor (ACCESS veya REFRESH)

**Sorular:**

#### **❓ `UserDetails` interface'i neden gerekli?**

**CEVAP:** Spring Security, kullanıcıyı tanımak için `UserDetails` interface'ine ihtiyaç duyar.

```java
// Spring Security'nin beklediği interface
public interface UserDetails {
  String getUsername();           // Kullanıcı adı (bizde email)
  String getPassword();           // Şifre (hashed)
  Collection<? extends GrantedAuthority> getAuthorities(); // Roller ve permission'lar
  boolean isAccountNonExpired();  // Hesap süresi dolmamış mı?
  boolean isAccountNonLocked();   // Hesap kilitli değil mi?
  boolean isCredentialsNonExpired(); // Şifre süresi dolmamış mı?
  boolean isEnabled();            // Hesap aktif mi?
}

// User entity'miz bu interface'i implement ediyor
public class User implements UserDetails {
  // Spring Security bu method'ları kullanarak user'ı tanıyor
}
```

**NEDEN:** Spring Security generic bir framework. Senin user entity'ni tanımıyor. `UserDetails` interface'i ile Spring Security'ye "kullanıcı bilgileri şu şekilde alınır" diyorsun.

---

#### **❓ `GrantedAuthority` nedir?**

**CEVAP:** Spring Security'nin **role** ve **permission** kavramını temsil eden interface.

```java
// Spring Security'nin beklediği interface
public interface GrantedAuthority {
  String getAuthority(); // "ROLE_ADMIN", "ROLE_USER", "admin:read", vb.
}

// User entity'mizde:
@Override
public Collection<? extends GrantedAuthority> getAuthorities() {
  // Role'ü GrantedAuthority'ye dönüştür
  var authorities = new ArrayList<GrantedAuthority>();
  authorities.add(new SimpleGrantedAuthority("ROLE_" + role.name())); // "ROLE_ADMIN"
  
  // Permission'ları da ekle
  authorities.addAll(role.getAuthorities()); // "admin:read", "admin:write", vb.
  
  return authorities;
}
```

**NEDEN:** Spring Security authorization yaparken `GrantedAuthority` listesine bakıyor. `@PreAuthorize("hasRole('ADMIN')")` annotation'ı bu listeyi kontrol ediyor.

---

#### **❓ Role ve Permission arasındaki fark nedir?**

**CEVAP:**

| Kavram | Açıklama | Örnek | Granularity |
|--------|----------|-------|-------------|
| **Role** | Kullanıcının genel rolü | `ADMIN`, `MANAGER`, `USER` | Coarse-grained (kaba) |
| **Permission** | Spesifik yetki | `admin:read`, `admin:write`, `admin:delete` | Fine-grained (ince) |

```java
// Role-based authorization (kaba)
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser() {
  // Sadece ADMIN rolü olan user'lar erişebilir
}

// Permission-based authorization (ince)
@PreAuthorize("hasAuthority('admin:delete')")
public void deleteUser() {
  // Sadece admin:delete permission'ı olan user'lar erişebilir
}
```

**NEDEN:** Role-based authorization basit ama esnek değil. Permission-based authorization daha granular kontrol sağlar.

**ÖRNEK:**
```java
// ADMIN rolü tüm permission'lara sahip
ADMIN.getPermissions() = [
  "admin:read",
  "admin:write",
  "admin:update",
  "admin:delete"
]

// MANAGER rolü sadece read ve write permission'larına sahip
MANAGER.getPermissions() = [
  "management:read",
  "management:write"
]
```

---

#### **❓ Token neden DB'de tutuluyor?**

**CEVAP:** **Token revocation** (iptal etme) için!

**JWT'nin Problemi:**
- JWT **stateless** → Server'da session tutmaz
- JWT **self-contained** → Token içinde user bilgisi var
- JWT **imzalı** → Signature valid olduğu sürece geçerli

**SORUN:** Logout yaptığında token'ı nasıl geçersiz kılacaksın?

```java
// ❌ YANLIŞ: JWT stateless, server'da session yok
// Logout yaptığında token hala geçerli!
POST /api/v1/auth/logout
// Token hala kullanılabilir! 🔴

// ✅ DOĞRU: Token'ı DB'de tut, revoke et
POST /api/v1/auth/logout
// Token DB'de revoked=true olarak işaretlenir
// Sonraki request'lerde token geçersiz! ✅
```

**Token Validation:**
```java
// JwtAuthenticationFilter içinde
var isTokenValid = tokenRepository.findByToken(jwt)
    .map(t -> !t.isExpired() && !t.isRevoked()) // DB'den kontrol et!
    .orElse(false);

if (!isTokenValid) {
  return; // Token revoked, request'i reddet!
}
```

**NEDEN DB'DE TUTUYORUZ:**
- ✅ **Token Revocation:** Logout sonrası token'ı geçersiz kıl
- ✅ **Security:** Çalınan token'ı blacklist'e al
- ✅ **Audit:** User'ın hangi cihazlardan login olduğunu gör
- ✅ **Multi-Device Logout:** Tüm cihazlardan logout yap

---

#### **❓ TokenType ve TokenPurpose arasındaki fark nedir?**

**CEVAP:**

| Enum | Açıklama | Değerler | Kullanım Amacı |
|------|----------|----------|----------------|
| **TokenType** | Token'ın **formatı** | `BEARER` | Authorization header formatı |
| **TokenPurpose** | Token'ın **amacı** | `ACCESS`, `REFRESH` | Token'ın ne için kullanıldığı |

```java
// TokenType: Token formatı
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
               ^^^^^^ TokenType.BEARER

// TokenPurpose: Token amacı
Token {
  token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  tokenType: BEARER,        // Format: Bearer token
  tokenPurpose: ACCESS      // Amaç: Access token (API erişimi için)
}

Token {
  token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  tokenType: BEARER,        // Format: Bearer token
  tokenPurpose: REFRESH     // Amaç: Refresh token (yeni access token almak için)
}
```

**NEDEN İKİ AYRI ENUM:**
- **TokenType:** Gelecekte farklı token formatları eklenebilir (Basic, Digest, vb.)
- **TokenPurpose:** Access ve refresh token'ları ayrı ayrı yönetmek için

**KULLANIM:**
```java
// Refresh token endpoint'inde sadece REFRESH token kabul et
var storedToken = tokenRepository.findByTokenAndTokenPurpose(
    jwt,
    TokenPurpose.REFRESH // Sadece REFRESH token'lar
).orElseThrow(() -> new RuntimeException("Invalid refresh token"));

// Access token ile refresh endpoint'e erişimi engelle!
```

---

### **ADIM 2: Repository Layer'ı Anla (Data Access)**

**Okuma Sırası:**
1. `UserRepository.java` - User data access
2. `TokenRepository.java` - Token data access
3. `BookRepository.java` - Book data access

**Dikkat Edilmesi Gerekenler:**
- ✅ `UserRepository.findByEmail()` - Login için kullanılıyor
- ✅ `TokenRepository.findAllValidTokenByUser()` - User'ın valid token'larını buluyor
- ✅ `TokenRepository.findAllValidTokenByUserAndPurpose()` - User'ın belirli purpose'taki valid token'larını buluyor
- ✅ `TokenRepository.findByToken()` - JWT token'ı validate ederken kullanılıyor
- ✅ `TokenRepository.findByTokenAndTokenPurpose()` - JWT token'ı purpose ile validate ederken kullanılıyor
- ⚠️ **BUG FİX:** `findAllValidTokenByUser()` query'sinde `OR` yerine `AND` kullanılmalı!

**Sorular:**

#### **❓ `Optional<User>` neden kullanılıyor?**

**CEVAP:** **Null safety** için!

```java
// ❌ YANLIŞ: Null döndür (NullPointerException riski!)
User findByEmail(String email); // null dönebilir!

User user = userRepository.findByEmail("test@example.com");
user.getPassword(); // NullPointerException! 💀

// ✅ DOĞRU: Optional döndür (null safety)
Optional<User> findByEmail(String email);

Optional<User> userOpt = userRepository.findByEmail("test@example.com");
User user = userOpt.orElseThrow(() -> new UsernameNotFoundException("User not found"));
// User bulunamazsa exception fırlat, NullPointerException yok! ✅
```

**NEDEN:** Java 8'den beri `Optional` kullanarak null safety sağlıyoruz. Null döndürmek yerine `Optional.empty()` döndürüyoruz.

---

#### **❓ `@Query` annotation'ı ne işe yarıyor?**

**CEVAP:** **Custom JPQL query** yazmak için!

```java
// Spring Data JPA otomatik query oluşturur
Optional<User> findByEmail(String email);
// SELECT * FROM users WHERE email = ?

// Ama complex query'ler için @Query kullanmalısın
@Query("""
    select t from Token t
    where t.user.id = :id and t.expired = false and t.revoked = false
    """)
List<Token> findAllValidTokenByUser(Integer id);
```

**NEDEN:** Spring Data JPA method naming convention'ı basit query'ler için yeterli. Ama complex query'ler için `@Query` kullanmalısın.

---

#### **❓ Token revocation nasıl çalışıyor?**

**CEVAP:** Token'ı DB'de `expired=true` ve `revoked=true` olarak işaretliyoruz.

```java
// 1. User logout yaptı
POST /api/v1/auth/logout
Authorization: Bearer <JWT>

// 2. LogoutService token'ı DB'de bulup revoke ediyor
var storedToken = tokenRepository.findByToken(jwt).orElse(null);
if (storedToken != null) {
  storedToken.setExpired(true);  // Token süresi doldu
  storedToken.setRevoked(true);  // Token iptal edildi
  tokenRepository.save(storedToken);
}

// 3. Sonraki request'lerde token geçersiz
GET /api/v1/books
Authorization: Bearer <JWT>

// JwtAuthenticationFilter içinde:
var isTokenValid = tokenRepository.findByToken(jwt)
    .map(t -> !t.isExpired() && !t.isRevoked()) // false döner!
    .orElse(false);

if (!isTokenValid) {
  return; // Token revoked, request'i reddet! ✅
}
```

---

#### **❓ TokenPurpose ile token filtreleme neden gerekli?**

**CEVAP:** **Access** ve **refresh** token'ları ayrı ayrı yönetmek için!

```java
// SENARYO: Refresh token ile yeni access token al
POST /api/v1/auth/refresh-token
Authorization: Bearer <REFRESH_TOKEN>

// AuthenticationService içinde:
// 1. Sadece eski ACCESS token'ları revoke et (REFRESH token korunsun!)
revokeAllUserTokensByPurpose(user.getId(), TokenPurpose.ACCESS);

// 2. Yeni access token oluştur
var accessToken = jwtService.generateToken(user);
saveUserToken(user, accessToken, TokenPurpose.ACCESS);

// 3. Refresh token aynı kalır!
return AuthenticationResponse.builder()
    .accessToken(accessToken)
    .refreshToken(refreshToken) // AYNI refresh token!
    .build();
```

**NEDEN:** Refresh token sırasında sadece access token'ları revoke etmeliyiz. Refresh token korunmalı!

---

### **ADIM 3: Config Layer'ı Anla (Spring Security Configuration)**

**Okuma Sırası:**
1. `ApplicationConfig.java` - Bean definitions
2. `SecurityConfiguration.java` - Security configuration
3. `JwtAuthenticationFilter.java` - JWT filter
4. `LogoutService.java` - Logout handler

**Dikkat Edilmesi Gerekenler:**

## 🧠 ApplicationConfig - Spring Security'nin Beyni

### **NE YAPIYOR?**

`ApplicationConfig`, Spring Security'nin ihtiyaç duyduğu **4 kritik bean**'i tanımlıyor:

1. **UserDetailsService** → "Kullanıcıyı nereden bulacaksın?"
2. **AuthenticationProvider** → "Kullanıcıyı nasıl doğrulayacaksın?"
3. **PasswordEncoder** → "Şifreyi nasıl kontrol edeceksin?"
4. **AuthenticationManager** → "Authentication işlemini kim koordine edecek?"

---

### **1️⃣ UserDetailsService Bean**

#### **NE:**
Kullanıcıyı **username** (bizde email) ile DB'den yükleyen servis.

#### **NEDEN:**
Spring Security senin user entity'ni tanımıyor! "Kullanıcıyı nereden bulacaksın?" sorusuna cevap veriyoruz.

#### **NASIL:**

```java
@Bean
public UserDetailsService userDetailsService() {
  return username -> userRepository.findByEmail(username)
      .orElseThrow(() -> new UsernameNotFoundException("User not found"));
}
```

#### **BU KOD NE DEMEK?**

Bu bir **lambda expression**. Aslında şu demek:

```java
// UserDetailsService bir FUNCTIONAL INTERFACE (tek abstract method var)
@FunctionalInterface
public interface UserDetailsService {
  UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}

// Lambda ile implement ediyoruz (kısa yol)
return username -> userRepository.findByEmail(username)
    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

// Yukarıdaki kod aslında şu demek (uzun yol):
return new UserDetailsService() {
  @Override
  public UserDetails loadUserByUsername(String username) {
    return userRepository.findByEmail(username)
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
  }
};
```

#### **NEDEN LAMBDA KULLANIYORUZ?**

- ✅ **Kısa ve okunabilir:** 1 satır vs 7 satır
- ✅ **Functional interface:** Tek method var, lambda kullanabiliriz
- ✅ **Modern Java:** Java 8+ lambda expression destekliyor

#### **BU BEAN NE ZAMAN KULLANILIYOR?**

```java
// SENARYO: Client login request gönderiyor
POST /api/v1/auth/authenticate
{ "email": "gokhan@example.com", "password": "12345" }

// Spring Security içinde:
// 1. AuthenticationManager çağrılır
// 2. AuthenticationManager, DaoAuthenticationProvider'ı çağırır
// 3. DaoAuthenticationProvider, UserDetailsService'i çağırır:

UserDetails user = userDetailsService.loadUserByUsername("gokhan@example.com");

// 4. UserDetailsService, DB'den kullanıcıyı bulur:
User user = userRepository.findByEmail("gokhan@example.com")
    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

// 5. User entity'si UserDetails interface'ini implement ediyor:
public class User implements UserDetails { ... }

// 6. Spring Security user'ı aldı! Şimdi şifreyi kontrol edecek...
```

#### **NEDEN User ENTITY'Sİ UserDetails IMPLEMENT EDİYOR?**

```java
// Spring Security'nin beklediği interface
public interface UserDetails {
  String getUsername();           // Kullanıcı adı (bizde email)
  String getPassword();           // Şifre (hashed)
  Collection<? extends GrantedAuthority> getAuthorities(); // Roller ve permissions
  boolean isAccountNonExpired();  // Hesap süresi dolmamış mı?
  boolean isAccountNonLocked();   // Hesap kilitli değil mi?
  boolean isCredentialsNonExpired(); // Şifre süresi dolmamış mı?
  boolean isEnabled();            // Hesap aktif mi?
}

// User entity'miz bu interface'i implement ediyor
@Entity
public class User implements UserDetails {
  
  @Column(unique = true)
  private String email;
  
  private String password;
  
  @Enumerated(EnumType.STRING)
  private Role role;
  
  // UserDetails method'larını implement ediyoruz
  @Override
  public String getUsername() {
    return email; // Bizde username = email
  }
  
  @Override
  public String getPassword() {
    return password; // Hashed password
  }
  
  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    // Role ve permissions'ları GrantedAuthority'ye dönüştür
    var authorities = new ArrayList<GrantedAuthority>();
    authorities.add(new SimpleGrantedAuthority("ROLE_" + role.name()));
    authorities.addAll(role.getAuthorities());
    return authorities;
  }
  
  @Override
  public boolean isAccountNonExpired() {
    return true; // Hesap süresi dolmuyor (şimdilik)
  }
  
  @Override
  public boolean isAccountNonLocked() {
    return true; // Hesap kilitlenmiyor (şimdilik)
  }
  
  @Override
  public boolean isCredentialsNonExpired() {
    return true; // Şifre süresi dolmuyor (şimdilik)
  }
  
  @Override
  public boolean isEnabled() {
    return true; // Hesap aktif (şimdilik)
  }
}
```

**NEDEN:** Spring Security generic bir framework. Senin user entity'ni tanımıyor. `UserDetails` interface'i ile Spring Security'ye "kullanıcı bilgileri şu şekilde alınır" diyorsun.

---

### **2️⃣ AuthenticationProvider Bean**

#### **NE:**
Kullanıcıyı **doğrulayan** (authenticate eden) provider.

#### **NEDEN:**
Spring Security'nin authentication yapması için bir provider lazım:
- ✅ Kullanıcı doğru mu? → Username DB'de var mı?
- ✅ Şifre doğru mu? → Password hash'i eşleşiyor mu?

#### **NASIL:**

```java
@Bean
public AuthenticationProvider authenticationProvider() {
  DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
  authProvider.setUserDetailsService(userDetailsService()); // Kullanıcıyı nereden bulacaksın?
  authProvider.setPasswordEncoder(passwordEncoder());       // Şifreyi nasıl kontrol edeceksin?
  return authProvider;
}
```

#### **BU KOD NE DEMEK?**

```java
// 1. DaoAuthenticationProvider oluştur (Spring Security'nin built-in class'ı)
DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

// 2. UserDetailsService'i set et (kullanıcıyı nereden bulacağını söyle)
authProvider.setUserDetailsService(userDetailsService());

// 3. PasswordEncoder'ı set et (şifreyi nasıl kontrol edeceğini söyle)
authProvider.setPasswordEncoder(passwordEncoder());

// 4. Provider'ı döndür (Spring Security kullanacak)
return authProvider;
```

#### **DaoAuthenticationProvider NE YAPIYOR?**

`DaoAuthenticationProvider` Spring Security'nin **built-in** class'ı. **Biz metotlarını override etmiyoruz, sadece configure ediyoruz!**

```java
// DaoAuthenticationProvider.java (Spring Security source code)
public class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

  private UserDetailsService userDetailsService;
  private PasswordEncoder passwordEncoder;
  
  // 1. ADIM: Kullanıcıyı yükle
  @Override
  protected final UserDetails retrieveUser(String username, 
                                           UsernamePasswordAuthenticationToken authentication) {
    try {
      // UserDetailsService'i çağır (BİZİM TANIMLADIĞIMIZ BEAN!)
      UserDetails loadedUser = this.userDetailsService.loadUserByUsername(username);
      
      if (loadedUser == null) {
        throw new InternalAuthenticationServiceException("UserDetailsService returned null");
      }
      return loadedUser;
      
    } catch (UsernameNotFoundException ex) {
      throw ex; // User bulunamadı!
    }
  }

  // 2. ADIM: Şifreyi kontrol et
  @Override
  protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                 UsernamePasswordAuthenticationToken authentication) {
    // Şifre gönderilmemiş mi?
    if (authentication.getCredentials() == null) {
      throw new BadCredentialsException("Bad credentials");
    }

    String presentedPassword = authentication.getCredentials().toString(); // Client'tan gelen şifre

    // PasswordEncoder ile şifreyi kontrol et (BİZİM TANIMLADIĞIMIZ BEAN!)
    if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
      throw new BadCredentialsException("Bad credentials"); // Şifre yanlış!
    }
  }

  // 3. ADIM: Başarılı authentication token oluştur
  @Override
  protected Authentication createSuccessAuthentication(Object principal,
                                                       Authentication authentication,
                                                       UserDetails user) {
    // Authentication token oluştur
    UsernamePasswordAuthenticationToken result = 
        new UsernamePasswordAuthenticationToken(
            principal,                      // User object
            authentication.getCredentials(), // Password (genelde null set edilir)
            user.getAuthorities()           // GrantedAuthorities (roles + permissions)
        );
    
    result.setDetails(authentication.getDetails());
    
    return result; // Bu token SecurityContext'e set edilecek!
  }
}
```

#### **BİZ NE YAPIYORUZ?**

Biz **sadece configure ediyoruz**, metotları override etmiyoruz:

```java
// ✅ BİZ SADECE CONFIGURE EDİYORUZ
@Bean
public AuthenticationProvider authenticationProvider() {
  DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
  authProvider.setUserDetailsService(userDetailsService()); // "Kullanıcıyı buradan bul"
  authProvider.setPasswordEncoder(passwordEncoder());       // "Şifreyi böyle kontrol et"
  return authProvider;
}

// ❌ METOTLARI OVERRIDE ETMİYORUZ (Spring Security default metotları kullanıyor)
// retrieveUser() → Spring Security'nin default implementasyonu
// additionalAuthenticationChecks() → Spring Security'nin default implementasyonu
// createSuccessAuthentication() → Spring Security'nin default implementasyonu
```

#### **AUTHENTICATION FLOW:**

```java
// Client login request gönderir
POST /api/v1/auth/authenticate
{ "email": "gokhan@example.com", "password": "12345" }

// DaoAuthenticationProvider.authenticate() çağrılır
// ↓
// 1. ADIM: retrieveUser() - Kullanıcıyı yükle
UserDetails user = userDetailsService.loadUserByUsername("gokhan@example.com");
// → userRepository.findByEmail("gokhan@example.com")
// → User { email: "gokhan@example.com", password: "$2a$10$..." }

// 2. ADIM: additionalAuthenticationChecks() - Şifreyi kontrol et
boolean passwordMatch = passwordEncoder.matches(
    "12345",                    // Client'tan gelen şifre (plain text)
    user.getPassword()          // DB'deki şifre (hashed: "$2a$10$...")
);
// → BCrypt.checkpw("12345", "$2a$10$...")
// → true ✅

// 3. ADIM: createSuccessAuthentication() - Authentication token oluştur
UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
    user,                       // Principal (User object)
    null,                       // Credentials (şifre artık gerek yok, güvenlik için null)
    user.getAuthorities()       // Authorities (roles + permissions)
);
// → authToken = {
//     principal: User { email: "gokhan@example.com", ... },
//     credentials: null,
//     authorities: ["ROLE_USER", "user:read", "user:write"]
//   }

// 4. ADIM: Authentication token döndür
return authToken;

// 5. ADIM: SecurityContext'e set edilir (JwtAuthenticationFilter içinde)
SecurityContextHolder.getContext().setAuthentication(authToken);
```

#### **NEDEN DaoAuthenticationProvider?**

Spring Security'de farklı provider'lar var:

| Provider | Authentication Type | Kullanım |
|----------|-------------------|----------|
| **DaoAuthenticationProvider** | Username/Password (DB) | **Bizim projede kullanılan** |
| `LdapAuthenticationProvider` | LDAP | Kurumsal uygulamalar |
| `JwtAuthenticationProvider` | JWT Token | Token-based auth |
| `RememberMeAuthenticationProvider` | Remember-me cookie | "Beni hatırla" özelliği |

**Biz `DaoAuthenticationProvider` kullanıyoruz çünkü:**
- ✅ Kullanıcıları **DB'de** tutuyoruz (PostgreSQL)
- ✅ Username/Password authentication yapıyoruz
- ✅ Spring Security'nin **default** ve **en yaygın** provider'ı

---

### **3️⃣ PasswordEncoder Bean**

#### **NE:**
Şifreyi **hashleyen** ve **doğrulayan** encoder.

#### **NEDEN:**
Şifreleri **plain text** olarak DB'de tutmak **BÜYÜK GÜVENLİK RİSKİ**:
- ❌ DB çalınırsa tüm şifreler açıkta!
- ✅ Şifreleri **hash**'leyerek saklıyoruz (BCrypt)
- ✅ BCrypt **one-way hash** → Geri döndürülemez!

#### **NASIL:**

```java
@Bean
public PasswordEncoder passwordEncoder() {
  return new BCryptPasswordEncoder();
}
```

#### **BCRYPT NASIL ÇALIŞIR?**

```java
// Plain text şifre
String plainPassword = "12345";

// BCrypt ile hashle
String hashedPassword = passwordEncoder.encode(plainPassword);
// Sonuç: $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy

// Her seferinde FARKLI hash üretir! (salt kullanır)
String hash1 = passwordEncoder.encode("12345");
// $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy

String hash2 = passwordEncoder.encode("12345");
// $2a$10$XYZ123differentHashButSamePassword456789abcdef

// Ama ikisi de aynı şifreyi doğrular!
passwordEncoder.matches("12345", hash1); // true ✅
passwordEncoder.matches("12345", hash2); // true ✅
passwordEncoder.matches("wrong", hash1); // false ❌
```

#### **REGISTER & LOGIN FLOW:**

```java
// ============================================
// 1. REGISTER: Kullanıcı kayıt olurken
// ============================================
POST /api/v1/auth/register
{ "email": "gokhan@example.com", "password": "12345" }

// AuthenticationService içinde:
var user = User.builder()
    .email(request.getEmail())
    .password(passwordEncoder.encode(request.getPassword())) // "12345" → hash
    .role(Role.USER)
    .build();
userRepository.save(user);

// DB'ye kaydedilen:
User {
  email: "gokhan@example.com",
  password: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
}

// ============================================
// 2. LOGIN: Kullanıcı login olurken
// ============================================
POST /api/v1/auth/authenticate
{ "email": "gokhan@example.com", "password": "12345" }

// DaoAuthenticationProvider içinde:
// 1. User'ı yükle
UserDetails user = userDetailsService.loadUserByUsername("gokhan@example.com");
// user.getPassword() = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// 2. Şifreyi kontrol et
boolean passwordMatch = passwordEncoder.matches(
    "12345",                    // Client'tan gelen (plain text)
    user.getPassword()          // DB'deki (hashed)
);
// passwordMatch = true ✅

// 3. Authentication başarılı!
```

#### **NEDEN BCRYPT?**

| Özellik | Açıklama |
|---------|----------|
| **One-way hash** | Hash'ten şifreyi geri çözemezsin |
| **Salt** | Her seferinde farklı hash üretir (aynı şifre bile) |
| **Slow** | Brute-force saldırılarını zorlaştırır (kasıtlı olarak yavaş) |
| **Adaptive** | Zaman içinde daha güçlü hale getirilebilir (cost factor artırılabilir) |

---

### **4️⃣ AuthenticationManager Bean**

#### **NE:**
Authentication işlemini **koordine eden** manager. Provider'ları yönetir.

#### **NEDEN:**
Spring Security'de authentication yapmak için **AuthenticationManager**'a ihtiyacımız var. AuthenticationManager, hangi provider'ın kullanılacağına karar verir ve authentication işlemini koordine eder.

#### **NASIL:**

```java
@Bean
public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
    throws Exception {
  return config.getAuthenticationManager();
}
```

#### **AuthenticationManager NE YAPIYOR?**

**ÖNEMLİ:** AuthenticationManager **kendisi authentication yapmıyor!** Sadece **provider'ları koordine ediyor**.

```java
// AuthenticationManager interface'i
public interface AuthenticationManager {
  Authentication authenticate(Authentication authentication) throws AuthenticationException;
}

// ProviderManager (AuthenticationManager'ın default implementation'ı)
public class ProviderManager implements AuthenticationManager {
  
  private List<AuthenticationProvider> providers; // Provider listesi
  
  @Override
  public Authentication authenticate(Authentication authentication) {
    
    // 1. Provider listesini dolaş
    for (AuthenticationProvider provider : providers) {
      
      // 2. Bu provider bu authentication type'ı destekliyor mu?
      if (provider.supports(authentication.getClass())) {
        
        try {
          // 3. Provider'a authentication'ı yaptır
          Authentication result = provider.authenticate(authentication);
          
          if (result != null) {
            return result; // Başarılı! Authentication döndür
          }
          
        } catch (AuthenticationException e) {
          // Authentication başarısız! Exception fırlat
          throw e;
        }
      }
    }
    
    // 4. Hiçbir provider desteklemedi!
    throw new ProviderNotFoundException("No provider found");
  }
}
```

#### **NEDEN BİRDEN FAZLA PROVIDER VAR?**

Farklı authentication mekanizmaları için farklı provider'lar kullanılabilir:

| Provider | Authentication Type | Kullanım |
|----------|-------------------|----------|
| **DaoAuthenticationProvider** | Username/Password (DB) | **Bizim projede kullanılan** |
| `LdapAuthenticationProvider` | LDAP | Kurumsal uygulamalar |
| `JwtAuthenticationProvider` | JWT Token | Token-based auth |
| `RememberMeAuthenticationProvider` | Remember-me cookie | "Beni hatırla" özelliği |

#### **BİZİM PROJEDEKİ DURUM:**

```java
// ApplicationConfig'de sadece 1 provider tanımlıyoruz
@Bean
public AuthenticationProvider authenticationProvider() {
  DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
  authProvider.setUserDetailsService(userDetailsService());
  authProvider.setPasswordEncoder(passwordEncoder());
  return authProvider;
}

// Spring Security otomatik olarak bu provider'ı AuthenticationManager'a ekliyor
// AuthenticationManager.providers = [DaoAuthenticationProvider]
```

#### **KULLANIM:**

```java
// AuthenticationService içinde
@RequiredArgsConstructor
public class AuthenticationService {
  
  private final AuthenticationManager authenticationManager; // Bean injection
  private final UserRepository repository;
  private final JwtService jwtService;
  
  public AuthenticationResponse authenticate(AuthenticationRequest request) {
    
    // ============================================
    // ADIM 1: AuthenticationManager'a authentication yaptır
    // ============================================
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),      // principal
            request.getPassword()    // credentials
        )
    );
    
    // AuthenticationManager içinde ne oluyor?
    // ↓
    // 1. Provider listesini dolaş → [DaoAuthenticationProvider]
    // 2. DaoAuthenticationProvider.supports(UsernamePasswordAuthenticationToken.class) → true
    // 3. DaoAuthenticationProvider.authenticate() çağrılır
    // 4. DaoAuthenticationProvider içinde:
    //    a) UserDetailsService ile user yüklenir
    //    b) PasswordEncoder ile password kontrol edilir
    //    c) Başarılı ise Authentication döner
    //    d) Başarısız ise BadCredentialsException fırlatılır
    
    // ============================================
    // ADIM 2: Authentication başarılı! JWT token oluştur
    // ============================================
    var user = repository.findByEmail(request.getEmail()).orElseThrow();
    var jwtToken = jwtService.generateToken(user);
    var refreshToken = jwtService.generateRefreshToken(user);
    
    // ============================================
    // ADIM 3: Response döndür
    // ============================================
    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
        .refreshToken(refreshToken)
        .build();
  }
}
```

#### **NEDEN DOĞRUDAN DaoAuthenticationProvider KULLANMIYORUZ?**

```java
// ❌ YANLIŞ: Provider'ı doğrudan kullan
@RequiredArgsConstructor
public class AuthenticationService {
  private final DaoAuthenticationProvider authenticationProvider;
  
  public void authenticate() {
    authenticationProvider.authenticate(...); // Tight coupling!
  }
}

// ✅ DOĞRU: AuthenticationManager kullan
@RequiredArgsConstructor
public class AuthenticationService {
  private final AuthenticationManager authenticationManager;
  
  public void authenticate() {
    authenticationManager.authenticate(...); // Loose coupling!
  }
}
```

**NEDEN:**
- ✅ **Loose coupling:** Provider değişirse kod değişmez
- ✅ **Extensibility:** Yeni provider eklemek kolay
- ✅ **Spring Security best practice:** AuthenticationManager kullan
- ✅ **Multiple providers:** Birden fazla provider kullanabilirsin

---

## 🎯 FULL PICTURE: 4 Bean Birlikte Nasıl Çalışır?

```java
// ============================================
// CLIENT REQUEST
// ============================================
POST /api/v1/auth/authenticate
{ "email": "gokhan@example.com", "password": "12345" }

// ============================================
// SPRING SECURITY AUTHENTICATION FLOW
// ============================================

1. AuthenticationController
   └─> authenticationManager.authenticate(
         new UsernamePasswordAuthenticationToken("gokhan@example.com", "12345")
       )

2. AuthenticationManager (ProviderManager)
   │
   ├─> Provider listesini dolaş: [DaoAuthenticationProvider]
   │
   ├─> DaoAuthenticationProvider.supports(UsernamePasswordAuthenticationToken.class)?
   │   └─> true ✅
   │
   └─> DaoAuthenticationProvider.authenticate(...)

3. DaoAuthenticationProvider
   │
   ├─> a) retrieveUser() - Kullanıcıyı yükle
   │      └─> UserDetailsService.loadUserByUsername("gokhan@example.com")
   │          └─> userRepository.findByEmail("gokhan@example.com")
   │              └─> User { email: "gokhan@example.com", password: "$2a$10$..." }
   │
   ├─> b) Kullanıcı bulundu mu kontrol et
   │      └─> if (user == null) throw UsernameNotFoundException ❌
   │      └─> User bulundu ✅
   │
   ├─> c) additionalAuthenticationChecks() - Şifreyi kontrol et
   │      └─> PasswordEncoder.matches("12345", "$2a$10$...")
   │          └─> BCrypt.checkpw("12345", "$2a$10$...")
   │              └─> true ✅
   │
   └─> d) createSuccessAuthentication() - Authentication token oluştur
       └─> new UsernamePasswordAuthenticationToken(
             user,                       // Principal
             null,                       // Credentials (artık gerek yok)
             user.getAuthorities()       // Authorities (roles + permissions)
           )
       └─> authToken = {
             principal: User { email: "gokhan@example.com", ... },
             credentials: null,
             authorities: ["ROLE_USER", "user:read", "user:write"]
           }

4. AuthenticationManager
   └─> Authentication token döndür (DaoAuthenticationProvider'dan gelen)

5. AuthenticationController
   │
   ├─> Authentication başarılı! ✅
   │
   ├─> User'ı DB'den tekrar al (JWT için)
   │   └─> var user = repository.findByEmail("gokhan@example.com").orElseThrow();
   │
   ├─> JWT token oluştur
   │   └─> var jwtToken = jwtService.generateToken(user);
   │   └─> var refreshToken = jwtService.generateRefreshToken(user);
   │
   └─> Response döndür
       └─> { "access_token": "eyJhbGc...", "refresh_token": "eyJhbGc..." }

// ============================================
// CLIENT RESPONSE
// ============================================
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

## 🔑 Authentication Token vs JWT Token

**ÇOK ÖNEMLİ:** `Authentication Token` ile `JWT Token` **FARKLI ŞEYLER!**

### **Authentication Token** (Spring Security Internal)

```java
// Spring Security'nin internal objesi
UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
    user,                    // principal (User object)
    null,                    // credentials (password - güvenlik için null)
    user.getAuthorities()    // authorities (roles + permissions)
);
```

**Ne İşe Yarar?**
- ✅ Spring Security'nin **internal state management**
- ✅ SecurityContext'te tutuluyor
- ✅ "Bu user authenticated mi?" kontrolü için
- ✅ "Bu user'ın rolleri/permissions neler?" bilgisi için
- ✅ **Backend'de kalıyor, client'a GÖNDERİLMİYOR!**

**Nerede Tutuluyor?**
```java
SecurityContextHolder.getContext().setAuthentication(authToken);
```

---

### **JWT Token** (Client-Server Communication)

```java
// Senin manuel oluşturduğun token
String jwtToken = jwtService.generateToken(user);
// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNjE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

**Ne İşe Yarar?**
- ✅ Client'a gönderiliyor
- ✅ Her request'te client tarafından gönderiliyor
- ✅ Stateless authentication için
- ✅ **Backend'den client'a GÖNDERİLİYOR!**

---

### **Karşılaştırma Tablosu**

| Özellik | Authentication Token | JWT Token |
|---------|---------------------|-----------|
| **Tip** | `UsernamePasswordAuthenticationToken` | `String` (encoded) |
| **Nerede?** | Backend (SecurityContext) | Client + Backend |
| **Amaç** | Spring Security internal state | Client-Server communication |
| **Ömür** | Request scope (her request'te yeniden oluşur) | Expiration time (örn: 24 saat) |
| **İçerik** | User object + Authorities | Encoded claims (username, roles, exp, iat) |
| **Client'a gönderilir mi?** | ❌ HAYIR | ✅ EVET |

---

## 🎓 ÖZET

### **ApplicationConfig 4 Bean Tanımlıyor:**

1. **UserDetailsService** → "Kullanıcıyı DB'den nasıl bulacaksın?"
   - Lambda expression ile implement ediyoruz
   - `userRepository.findByEmail()` kullanıyoruz

2. **AuthenticationProvider** → "Kullanıcıyı nasıl doğrulayacaksın?"
   - `DaoAuthenticationProvider` kullanıyoruz (Spring Security'nin built-in class'ı)
   - **Biz metotları override etmiyoruz, sadece configure ediyoruz!**
   - UserDetailsService ve PasswordEncoder'ı set ediyoruz

3. **PasswordEncoder** → "Şifreyi nasıl kontrol edeceksin?"
   - `BCryptPasswordEncoder` kullanıyoruz
   - One-way hash, salt, slow, adaptive

4. **AuthenticationManager** → "Authentication işlemini kim koordine edecek?"
   - Provider'ları yönetir
   - **Kendisi authentication yapmıyor, provider'lara yaptırıyor!**
   - Loose coupling için AuthenticationManager kullanıyoruz

### **Authentication Flow:**

```
Client Request
    ↓
AuthenticationController
    ↓
AuthenticationManager (provider'ları koordine eder)
    ↓
DaoAuthenticationProvider (authentication yapar)
    ├─> UserDetailsService (user yükle)
    ├─> PasswordEncoder (password kontrol et)
    └─> Authentication token oluştur
    ↓
AuthenticationController
    ├─> JWT token oluştur
    └─> Response döndür
```

### **Kritik Noktalar:**

- ✅ **UserDetailsService:** Lambda expression ile implement ediyoruz (functional interface)
- ✅ **DaoAuthenticationProvider:** Spring Security'nin default metotlarını kullanıyoruz, override etmiyoruz
- ✅ **AuthenticationManager:** Provider'ları koordine eder, kendisi authentication yapmaz
- ✅ **Authentication Token ≠ JWT Token:** İkisi farklı şeyler!


---

#### **SecurityConfiguration.java:**
- ✅ `securityFilterChain()` - Filter chain configuration
- ✅ Whitelisted URLs: `/api/v1/auth/**` (permitAll)
- ✅ Role-based authorization: `/api/v1/admin/**` (ADMIN only)
- ✅ Permission-based authorization: `/api/v1/management/**` (specific permissions)
- ✅ Stateless session management: `SessionCreationPolicy.STATELESS`
- ✅ JWT filter: `addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)`

#### **JwtAuthenticationFilter.java:**
- ✅ `OncePerRequestFilter` extend ediyor (her request'te bir kez çalışır)
- ✅ Authorization header'dan JWT token'ı alıyor
- ✅ Token'ı validate ediyor (signature, expiration, revocation)
- ✅ User'ı yüklüyor (`UserDetailsService`)
- ✅ SecurityContext'e Authentication set ediyor

#### **LogoutService.java:**
- ✅ `LogoutHandler` interface'ini implement ediyor
- ✅ User'ın TÜM token'larını bulup revoke ediyor (ACCESS + REFRESH)
- ✅ SecurityContext'i temizliyor

**Sorular:**

#### **❓ `UserDetailsService` neden bean olarak tanımlanıyor?**

**CEVAP:** Spring Security'nin **dependency injection** ile kullanabilmesi için!

```java
// ApplicationConfig'de bean olarak tanımlıyoruz
@Bean
public UserDetailsService userDetailsService() {
  return username -> userRepository.findByEmail(username)
      .orElseThrow(() -> new UsernameNotFoundException("User not found"));
}

// AuthenticationProvider bu bean'i kullanıyor
@Bean
public AuthenticationProvider authenticationProvider() {
  DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
  authProvider.setUserDetailsService(userDetailsService()); // Bean injection!
  return authProvider;
}

// JwtAuthenticationFilter da bu bean'i kullanıyor
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  private final UserDetailsService userDetailsService; // Bean injection!
  
  // ...
  UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
}
```

**NEDEN:** Spring'in **IoC (Inversion of Control)** prensibi. Bean'leri Spring container yönetiyor, biz sadece inject ediyoruz.

---

#### **❓ `AuthenticationProvider` ne işe yarıyor?**

**CEVAP:** Kullanıcıyı **doğrulamak** (authenticate etmek) için!

```java
// AuthenticationProvider'ın görevi:
1. UserDetailsService'ten kullanıcıyı yükle
2. Kullanıcı bulundu mu kontrol et
3. PasswordEncoder ile şifreyi kontrol et
4. Her şey doğruysa Authentication objesi döndür
```

**NEDEN:** Spring Security'nin authentication mekanizması **pluggable** (takılabilir). Farklı authentication provider'lar kullanabilirsin:
- `DaoAuthenticationProvider` → DB'den kullanıcı yükle
- `LdapAuthenticationProvider` → LDAP'tan kullanıcı yükle
- `JwtAuthenticationProvider` → JWT token'dan kullanıcı yükle

---

#### **❓ Filter chain sırası neden önemli?**

**CEVAP:** Filter'lar **sırayla** çalışır! Yanlış sırada olursa authentication çalışmaz.

```java
// ✅ DOĞRU SIRA:
1. SecurityContextPersistenceFilter (SecurityContext yükle)
2. JwtAuthenticationFilter (JWT token validate et) ← BİZİM CUSTOM FILTER
3. UsernamePasswordAuthenticationFilter (username/password authentication)
4. ExceptionTranslationFilter (exception handling)
5. FilterSecurityInterceptor (authorization - role/permission kontrolü)

// ❌ YANLIŞ SIRA:
1. FilterSecurityInterceptor (authorization) ← İLK ÖNCE AUTHORIZATION YAPILIR
2. JwtAuthenticationFilter (authentication) ← SONRA AUTHENTICATION YAPILIR
// SORUN: Authorization yaparken user henüz authenticated değil! 🔴
```

**NEDEN:** Authentication **önce** yapılmalı, authorization **sonra** yapılmalı!

---

#### **❓ `SessionCreationPolicy.STATELESS` ne demek?**

**CEVAP:** Server'da **session tutma**, her request'te JWT token gönder!

```java
// STATEFUL (Session-based):
http.sessionManagement()
    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); // Session oluştur

// Client login yaptı → Server session oluşturdu (memory/database)
// Client request attı → Session ID gönderdi
// Server session'dan user'ı yükledi

// STATELESS (JWT-based):
http.sessionManagement()
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS); // Session oluşturma!

// Client login yaptı → Server JWT token döndü (session yok!)
// Client request attı → JWT token gönderdi
// Server JWT'den user'ı yükledi (session yok!)
```

**NEDEN:** JWT **stateless** authentication için tasarlandı. Session tutmaya gerek yok!

---

#### **❓ SecurityContext nedir, nasıl çalışır?**

**CEVAP:** Spring Security'nin **thread-local storage**'ı. Her thread için ayrı bir SecurityContext tutar.

```java
// JwtAuthenticationFilter içinde:
// 1. User'ı authenticate et
UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
    userDetails,
    null,
    userDetails.getAuthorities()
);

// 2. SecurityContext'e set et
SecurityContextHolder.getContext().setAuthentication(authToken);

// 3. Controller'da current user'ı al
@GetMapping("/me")
public User getCurrentUser() {
  Authentication auth = SecurityContextHolder.getContext().getAuthentication();
  return (User) auth.getPrincipal(); // Current user!
}

// 4. @AuthenticationPrincipal annotation'ı ile de alabilirsin
@GetMapping("/me")
public User getCurrentUser(@AuthenticationPrincipal User user) {
  return user; // Current user!
}
```

**NEDEN:** SecurityContext **thread-local** → Her thread için ayrı. Multi-threaded environment'ta güvenli!

---

### **ADIM 4: Service Layer'ı Anla (Business Logic)**

**Okuma Sırası:**
1. `JwtService.java` - JWT token operations
2. `AuthenticationService.java` - Authentication logic
3. `UserService.java` - User operations
4. `BookService.java` - Book operations

**Dikkat Edilmesi Gerekenler:**

#### **JwtService.java:**
- ✅ `extractUsername()` - JWT'den username (email) çıkarıyor
- ✅ `generateToken()` - Access token oluşturuyor (24 saat)
- ✅ `generateRefreshToken()` - Refresh token oluşturuyor (7 gün)
- ✅ `isTokenValid()` - Token'ı validate ediyor
- ⚠️ **SECURITY WARNING:** Secret key hardcoded (externalize edilmeli!)
- ⚠️ **DEPRECATED:** `SignatureAlgorithm.HS256` yerine `HS512` kullanılmalı!

#### **AuthenticationService.java:**
- ✅ `register()` - User kaydı + token generation (ACCESS + REFRESH)
- ✅ `authenticate()` - Login + token generation (ACCESS + REFRESH)
- ✅ `refreshToken()` - Refresh token ile yeni access token alma
- ✅ `saveUserToken()` - Token'ı DB'ye kaydetme (TokenPurpose ile)
- ✅ `revokeAllUserTokens()` - User'ın tüm token'larını revoke etme (ACCESS + REFRESH)
- ✅ `revokeAllUserTokensByPurpose()` - User'ın belirli purpose'taki token'larını revoke etme (sadece ACCESS veya sadece REFRESH)

#### **UserService.java:**
- ✅ `changePassword()` - Password değiştirme
- ✅ Eski password kontrolü yapıyor
- ✅ Yeni password'ü BCrypt ile hashliyor

**Sorular:**

#### **❓ JWT token nasıl oluşturuluyor?**

**CEVAP:**

```java
// JwtService içinde:
public String generateToken(UserDetails userDetails) {
  return Jwts.builder()
      .setSubject(userDetails.getUsername())           // Subject: email
      .setIssuedAt(new Date(System.currentTimeMillis())) // Issued at: şimdi
      .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // Expiration: 24 saat
      .signWith(getSignInKey(), SignatureAlgorithm.HS256) // Signature: HMAC SHA256
      .compact();
}

// Oluşan JWT token:
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJnb2toYW5AZXhhbXBsZS5jb20iLCJpYXQiOjE2MzAwMDAwMDAsImV4cCI6MTYzMDA4NjQwMH0.signature
// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^
// Header (algorithm, type)          Payload (subject, issued at, expiration)                                   Signature
```

---

#### **❓ Access token ve refresh token arasındaki fark nedir?**

**CEVAP:**

| Token | Amaç | Expiration | Kullanım |
|-------|------|------------|----------|
| **Access Token** | API erişimi | 24 saat (kısa) | Her request'te gönderilir |
| **Refresh Token** | Yeni access token alma | 7 gün (uzun) | Sadece refresh endpoint'inde gönderilir |

```java
// Access token: API erişimi için
GET /api/v1/books
Authorization: Bearer <ACCESS_TOKEN>

// Refresh token: Yeni access token almak için
POST /api/v1/auth/refresh-token
Authorization: Bearer <REFRESH_TOKEN>
```

**NEDEN:** Access token kısa ömürlü → Çalınırsa kısa süre kullanılabilir. Refresh token uzun ömürlü → Yeni access token almak için.

---

#### **❓ Token revocation neden gerekli?**

**CEVAP:** Logout sonrası token'ı geçersiz kılmak için!

```java
// Logout yaptığında token'ı revoke et
POST /api/v1/auth/logout
Authorization: Bearer <JWT>

// LogoutService içinde:
var allUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
allUserTokens.forEach(token -> {
  token.setExpired(true);
  token.setRevoked(true);
});
tokenRepository.saveAll(allUserTokens);

// Sonraki request'lerde token geçersiz
GET /api/v1/books
Authorization: Bearer <JWT>
// 403 Forbidden (Token revoked!)
```

---

#### **❓ BCrypt neden kullanılıyor?**

**CEVAP:** Şifreleri **güvenli** bir şekilde hashlemek için!

**BCrypt Özellikleri:**
- ✅ **One-way hash:** Hash'ten şifreyi geri çözemezsin
- ✅ **Salt:** Her seferinde farklı hash üretir (aynı şifre bile)
- ✅ **Slow:** Brute-force saldırılarını zorlaştırır
- ✅ **Adaptive:** Zaman içinde daha güçlü hale getirilebilir

---

#### **❓ Refresh token sırasında neden sadece ACCESS token'lar revoke ediliyor?**

**CEVAP:** Refresh token **korunmalı**, sadece access token yenilenmeli!

```java
// Refresh token endpoint'inde:
POST /api/v1/auth/refresh-token
Authorization: Bearer <REFRESH_TOKEN>

// AuthenticationService içinde:
// 1. Sadece eski ACCESS token'ları revoke et (REFRESH token korunsun!)
revokeAllUserTokensByPurpose(user.getId(), TokenPurpose.ACCESS);

// 2. Yeni access token oluştur
var accessToken = jwtService.generateToken(user);
saveUserToken(user, accessToken, TokenPurpose.ACCESS);

// 3. Refresh token aynı kalır!
return AuthenticationResponse.builder()
    .accessToken(accessToken)      // YENİ access token
    .refreshToken(refreshToken)    // AYNI refresh token
    .build();
```

**NEDEN:** Refresh token uzun ömürlü. Her refresh'te yeni refresh token oluşturmak gereksiz. Sadece access token yenilenmeli!

---

### **ADIM 5: Controller Layer'ı Anla (REST API)**

**Okuma Sırası:**
1. `AuthenticationController.java` - Auth endpoints
2. `UserController.java` - User endpoints
3. `BookController.java` - Book endpoints
4. `DemoController.java`, `AdminController.java`, `ManagementController.java` - Demo endpoints

**Dikkat Edilmesi Gerekenler:**

#### **AuthenticationController.java:**
- ✅ `POST /api/v1/auth/register` - User registration
- ✅ `POST /api/v1/auth/authenticate` - Login
- ✅ `POST /api/v1/auth/refresh-token` - Refresh token

#### **UserController.java:**
- ✅ `PATCH /api/v1/users` - Change password
- ✅ `@PreAuthorize("hasRole('USER')")` - Role-based authorization

#### **BookController.java:**
- ✅ `POST /api/v1/books` - Create book
- ✅ `GET /api/v1/books` - Get all books
- ✅ `@PreAuthorize("hasRole('ADMIN')")` - Admin-only endpoint

#### **Demo Controllers:**
- ✅ `AdminController` - `@PreAuthorize("hasRole('ADMIN')")`
- ✅ `ManagementController` - `@PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")`

**Sorular:**

#### **❓ `@PreAuthorize` annotation'ı nasıl çalışıyor?**

**CEVAP:** Spring Security **method-level authorization** için kullanılıyor.

```java
// Role-based authorization
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin")
public String adminEndpoint() {
  return "Admin only!";
}

// Permission-based authorization
@PreAuthorize("hasAuthority('admin:read')")
@GetMapping("/admin/read")
public String adminReadEndpoint() {
  return "Admin read only!";
}

// Multiple roles
@PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
@GetMapping("/management")
public String managementEndpoint() {
  return "Admin or Manager!";
}
```

**NASIL ÇALIŞIR:**
1. Client request atar
2. JwtAuthenticationFilter JWT token'ı validate eder
3. SecurityContext'e Authentication set eder
4. `@PreAuthorize` annotation'ı Authentication'daki authorities'i kontrol eder
5. Yetki varsa method çalışır, yoksa 403 Forbidden döner

---

#### **❓ `@AuthenticationPrincipal` ne işe yarıyor?**

**CEVAP:** SecurityContext'ten **current user**'ı almak için!

```java
// ❌ YANLIŞ: SecurityContextHolder kullan (verbose)
@GetMapping("/me")
public User getCurrentUser() {
  Authentication auth = SecurityContextHolder.getContext().getAuthentication();
  return (User) auth.getPrincipal();
}

// ✅ DOĞRU: @AuthenticationPrincipal kullan (clean