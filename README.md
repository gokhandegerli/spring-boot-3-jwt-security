# 🔐 Spring Boot 3.0 Security with JWT Implementation

Bu proje, **Spring Boot 3.0** ve **JSON Web Tokens (JWT)** kullanarak modern, stateless authentication ve authorization sisteminin nasıl implement edileceğini gösterir.

---

## 📋 İçindekiler

1. [Özellikler](#-özellikler)
2. [Teknolojiler](#-teknolojiler)
3. [Kurulum](#-kurulum)
4. [Spring Security Felsefesi](#-spring-security-felsefesi)
5. [JWT Authentication Flow](#-jwt-authentication-flow)
6. [ApplicationConfig - Spring Security'nin Beyni](#-applicationconfig---spring-securitynin-beyni)
7. [SecurityConfiguration - Filter Chain](#-securityconfiguration---filter-chain)
8. [JwtAuthenticationFilter - Token Validation](#-jwtauthenticationfilter---token-validation)
9. [Proje Mimarisi](#-proje-mimarisi)
10. [API Endpoints](#-api-endpoints)
11. [Güvenlik Notları](#-güvenlik-notları)

---

## ✨ Özellikler

- ✅ **User Registration & Login** - JWT authentication ile kullanıcı kaydı ve girişi
- ✅ **Password Encryption** - BCrypt ile şifre hashleme
- ✅ **Role-Based Authorization** - Spring Security ile rol bazlı yetkilendirme
- ✅ **Permission-Based Authorization** - Granular permission kontrolü
- ✅ **JWT Access Token** - Stateless authentication için JWT token
- ✅ **JWT Refresh Token** - Access token yenilemek için refresh token
- ✅ **Token Revocation** - Logout ile token iptal etme
- ✅ **Stateless Session Management** - Server'da session tutmadan authentication

---

## 🛠 Teknolojiler

| Teknoloji | Versiyon | Açıklama |
|-----------|----------|----------|
| **Java** | 17+ | Modern Java features |
| **Spring Boot** | 3.0+ | Framework |
| **Spring Security** | 6.0+ | Authentication & Authorization |
| **Spring Data JPA** | 3.0+ | Database ORM |
| **PostgreSQL** | 14+ | Relational database |
| **JJWT** | 0.11.5 | JWT token generation & validation |
| **BCrypt** | - | Password hashing algorithm |
| **Lombok** | 1.18.26 | Boilerplate code reduction |

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

4. **Projeyi çalıştır:**
   ```bash
   mvn spring-boot:run
   ```

5. **Uygulamaya eriş:**
    - API: http://localhost:8080
    - Swagger UI: http://localhost:8080/swagger-ui.html

---

## 🧠 Spring Security Felsefesi

### **1. Authentication vs Authorization**

| Kavram | Açıklama | Örnek |
|--------|----------|-------|
| **Authentication** | "Sen kimsin?" sorusuna cevap | Login (email + password) |
| **Authorization** | "Ne yapma yetkin var?" sorusuna cevap | Admin paneline erişim |

---

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

**ÖNEMLİ:** Filter sırası kritik! Authentication **önce**, authorization **sonra** yapılmalı.

---

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

**NEDEN:** SecurityContext **thread-local** → Her thread için ayrı. Multi-threaded environment'ta güvenli!

---

### **4. Stateless Authentication**

**Stateful (Session-based):**
- ❌ Server'da session tutar (memory/database)
- ❌ Scalability sorunu (load balancer, multiple server)

**Stateless (JWT-based):**
- ✅ Server'da session tutmaz
- ✅ Her request'te JWT token gönderilir
- ✅ Token içinde user bilgisi var (self-contained)
- ✅ Horizontal scaling kolay

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
  |                               | 3. JWT access token oluştur
  |                               | 4. JWT refresh token oluştur
  |                               | 5. Token'ları DB'ye kaydet
  |                               |
  |  { access_token, refresh_token }
  |<------------------------------|
```

---

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
  |                               | 4. JWT access token oluştur
  |                               | 5. JWT refresh token oluştur
  |                               | 6. Eski token'ları revoke et
  |                               | 7. Yeni token'ları DB'ye kaydet
  |                               |
  |  { access_token, refresh_token }
  |<------------------------------|
```

---

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
  |                               | 5. SecurityContext'e Authentication set et
  |                               |
  |                               | FilterSecurityInterceptor:
  |                               | 6. Role/Permission kontrolü yap
  |                               | 7. Controller method'u çağır
  |                               |
  |  [ { book1 }, { book2 }, ... ] |
  |<------------------------------|
```

---

### **4. Refresh Token Flow**

```
Client                          Server
  |                               |
  |  POST /api/v1/auth/refresh-token |
  |  Authorization: Bearer <REFRESH_TOKEN> |
  |------------------------------>|
  |                               |
  |                               | 1. Refresh token'ı validate et
  |                               | 2. User'ı DB'den yükle
  |                               | 3. Yeni access token oluştur
  |                               | 4. Eski access token'ları revoke et
  |                               | 5. Yeni access token'ı DB'ye kaydet
  |                               |
  |  { access_token, refresh_token }
  |  (refresh_token aynı kalır)   |
  |<------------------------------|
```

---

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
  |                               | 3. TÜM token'ları revoke et
  |                               | 4. SecurityContext'i temizle
  |                               |
  |  200 OK                       |
  |<------------------------------|
```

---

## 🧠 ApplicationConfig - Spring Security'nin Beyni

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
```

#### **BU BEAN NE ZAMAN KULLANILIYOR?**

```java
// SENARYO: Client login request gönderiyor
POST /api/v1/auth/authenticate
{ "email": "gokhan@example.com", "password": "12345" }

// Spring Security içinde:
// 1. AuthenticationManager çağrılır
// 2. DaoAuthenticationProvider çağrılır
// 3. UserDetailsService çağrılır:

UserDetails user = userDetailsService.loadUserByUsername("gokhan@example.com");

// 4. User entity'si UserDetails interface'ini implement ediyor
public class User implements UserDetails { ... }
```

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

#### **DaoAuthenticationProvider NE YAPIYOR?**

`DaoAuthenticationProvider` Spring Security'nin **built-in** class'ı. **Biz metotlarını override etmiyoruz, sadece configure ediyoruz!**

```java
// DaoAuthenticationProvider içinde (Spring Security source code):

// 1. ADIM: Kullanıcıyı yükle
UserDetails user = userDetailsService.loadUserByUsername(username);

// 2. ADIM: Şifreyi kontrol et
if (!passwordEncoder.matches(presentedPassword, user.getPassword())) {
  throw new BadCredentialsException("Bad credentials");
}

// 3. ADIM: Authentication token oluştur
UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
    user,                       // Principal
    null,                       // Credentials (artık gerek yok)
    user.getAuthorities()       // Authorities (roles + permissions)
);

return authToken;
```

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
String hash2 = passwordEncoder.encode("12345");
// hash1 ≠ hash2

// Ama ikisi de aynı şifreyi doğrular!
passwordEncoder.matches("12345", hash1); // true ✅
passwordEncoder.matches("12345", hash2); // true ✅
```

#### **NEDEN BCRYPT?**

| Özellik | Açıklama |
|---------|----------|
| **One-way hash** | Hash'ten şifreyi geri çözemezsin |
| **Salt** | Her seferinde farklı hash üretir |
| **Slow** | Brute-force saldırılarını zorlaştırır |
| **Adaptive** | Zaman içinde daha güçlü hale getirilebilir |

---

### **4️⃣ AuthenticationManager Bean**

#### **NE:**
Authentication işlemini **koordine eden** manager. Provider'ları yönetir.

#### **NEDEN:**
Spring Security'de authentication yapmak için **AuthenticationManager**'a ihtiyacımız var.

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
// ProviderManager (AuthenticationManager'ın default implementation'ı)
public class ProviderManager implements AuthenticationManager {
  
  private List<AuthenticationProvider> providers; // Provider listesi
  
  @Override
  public Authentication authenticate(Authentication authentication) {
    
    // 1. Provider listesini dolaş
    for (AuthenticationProvider provider : providers) {
      
      // 2. Bu provider bu authentication type'ı destekliyor mu?
      if (provider.supports(authentication.getClass())) {
        
        // 3. Provider'a authentication'ı yaptır
        Authentication result = provider.authenticate(authentication);
        
        if (result != null) {
          return result; // Başarılı!
        }
      }
    }
    
    throw new ProviderNotFoundException("No provider found");
  }
}
```

#### **KULLANIM:**

```java
// AuthenticationService içinde
public AuthenticationResponse authenticate(AuthenticationRequest request) {
  
  // AuthenticationManager'a authentication yaptır
  authenticationManager.authenticate(
      new UsernamePasswordAuthenticationToken(
          request.getEmail(),
          request.getPassword()
      )
  );
  
  // Authentication başarılı! JWT token oluştur
  var user = repository.findByEmail(request.getEmail()).orElseThrow();
  var jwtToken = jwtService.generateToken(user);
  var refreshToken = jwtService.generateRefreshToken(user);
  
  return AuthenticationResponse.builder()
      .accessToken(jwtToken)
      .refreshToken(refreshToken)
      .build();
}
```

---

### **🎯 FULL PICTURE: 4 Bean Birlikte Nasıl Çalışır?**

```
Client Request
    ↓
POST /api/v1/auth/authenticate
{ "email": "gokhan@example.com", "password": "12345" }
    ↓
AuthenticationController
    ↓
AuthenticationManager.authenticate()
    ↓
DaoAuthenticationProvider.authenticate()
    ├─> UserDetailsService.loadUserByUsername("gokhan@example.com")
    │   └─> userRepository.findByEmail("gokhan@example.com")
    │       └─> User { email: "gokhan@example.com", password: "$2a$10$..." }
    │
    ├─> PasswordEncoder.matches("12345", "$2a$10$...")
    │   └─> BCrypt.checkpw("12345", "$2a$10$...")
    │       └─> true ✅
    │
    └─> new UsernamePasswordAuthenticationToken(user, null, authorities)
        └─> authToken = {
              principal: User { email: "gokhan@example.com", ... },
              credentials: null,
              authorities: ["ROLE_USER", "user:read", "user:write"]
            }
    ↓
AuthenticationController
    ├─> JWT token oluştur
    └─> Response döndür
    ↓
{ "access_token": "eyJhbGc...", "refresh_token": "eyJhbGc..." }
```

---

### **🔑 Authentication Token vs JWT Token**

**ÇOK ÖNEMLİ:** `Authentication Token` ile `JWT Token` **FARKLI ŞEYLER!**

| Özellik | Authentication Token | JWT Token |
|---------|---------------------|-----------|
| **Tip** | `UsernamePasswordAuthenticationToken` | `String` (encoded) |
| **Nerede?** | Backend (SecurityContext) | Client + Backend |
| **Amaç** | Spring Security internal state | Client-Server communication |
| **Ömür** | Request scope | Expiration time (örn: 24 saat) |
| **Client'a gönderilir mi?** | ❌ HAYIR | ✅ EVET |

---

## 🔒 SecurityConfiguration - Filter Chain

`SecurityConfiguration`, Spring Security'nin **filter chain**'ini configure ediyor.

### **Temel Konfigürasyon:**

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
  http
      // 1. CSRF disable (JWT kullanıyoruz, CSRF'e gerek yok)
      .csrf(AbstractHttpConfigurer::disable)
      
      // 2. URL authorization rules
      .authorizeHttpRequests(auth -> auth
          // Public endpoints (permitAll)
          .requestMatchers("/api/v1/auth/**").permitAll()
          
          // Admin-only endpoints
          .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
          
          // Permission-based endpoints
          .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority("admin:read", "management:read")
          .requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority("admin:create", "management:create")
          
          // Diğer tüm endpoint'ler authenticated olmalı
          .anyRequest().authenticated()
      )
      
      // 3. Stateless session management
      .sessionManagement(session -> session
          .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
      )
      
      // 4. Authentication provider
      .authenticationProvider(authenticationProvider)
      
      // 5. JWT filter (UsernamePasswordAuthenticationFilter'dan ÖNCE)
      .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
      
      // 6. Logout handler
      .logout(logout -> logout
          .logoutUrl("/api/v1/auth/logout")
          .addLogoutHandler(logoutHandler)
          .logoutSuccessHandler((request, response, authentication) -> 
              SecurityContextHolder.clearContext()
          )
      );
  
  return http.build();
}
```

### **Kritik Noktalar:**

#### **1. CSRF Neden Disable?**

```java
.csrf(AbstractHttpConfigurer::disable)
```

**NEDEN:** JWT kullanıyoruz, CSRF token'a gerek yok!

- **CSRF (Cross-Site Request Forgery):** Cookie-based authentication'da gerekli
- **JWT:** Stateless, cookie kullanmıyor → CSRF'e gerek yok

---

#### **2. Stateless Session Management**

```java
.sessionManagement(session -> session
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
)
```

**NEDEN:** Server'da session tutmuyoruz, JWT kullanıyoruz!

---

#### **3. Filter Sırası**

```java
.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
```

**NEDEN:** JWT filter **önce** çalışmalı, sonra Spring Security'nin default filter'ları çalışmalı!

---

## 🔍 JwtAuthenticationFilter - Token Validation

`JwtAuthenticationFilter`, her request'te JWT token'ı validate ediyor.

### **Filter Akışı:**

```java
@Override
protected void doFilterInternal(
    HttpServletRequest request,
    HttpServletResponse response,
    FilterChain filterChain
) throws ServletException, IOException {
  
  // 1. Authorization header'ı al
  final String authHeader = request.getHeader("Authorization");
  
  // 2. Header yoksa veya "Bearer " ile başlamıyorsa, skip
  if (authHeader == null || !authHeader.startsWith("Bearer ")) {
    filterChain.doFilter(request, response);
    return;
  }
  
  // 3. JWT token'ı çıkar
  final String jwt = authHeader.substring(7);
  
  // 4. JWT'den username (email) çıkar
  final String userEmail = jwtService.extractUsername(jwt);
  
  // 5. User authenticated değilse
  if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
    
    // 6. User'ı DB'den yükle
    UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
    
    // 7. Token'ı validate et
    var isTokenValid = tokenRepository.findByToken(jwt)
        .map(t -> !t.isExpired() && !t.isRevoked())
        .orElse(false);
    
    // 8. Token valid ise SecurityContext'e set et
    if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
      UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
          userDetails,
          null,
          userDetails.getAuthorities()
      );
      
      authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
      
      SecurityContextHolder.getContext().setAuthentication(authToken);
    }
  }
  
  // 9. Sonraki filter'a geç
  filterChain.doFilter(request, response);
}
```

### **Token Validation Kriterleri:**

1. ✅ **Signature valid mi?** → `jwtService.isTokenValid()`
2. ✅ **Expired değil mi?** → JWT expiration claim
3. ✅ **Revoked değil mi?** → DB'de `revoked=false`
4. ✅ **User mevcut mu?** → `userDetailsService.loadUserByUsername()`

---

## 🏗 Proje Mimarisi

### **Package Structure**

```
com.degerli.security
├── config/                          # Security Configuration
│   ├── ApplicationConfig.java       # Bean definitions
│   ├── JwtAuthenticationFilter.java # JWT filter
│   ├── LogoutService.java           # Logout handler
│   └── SecurityConfiguration.java   # Security configuration
│
├── user/                            # User Domain
│   ├── User.java                    # User entity (UserDetails implementation)
│   ├── Role.java                    # Role enum (ADMIN, MANAGER, USER)
│   ├── Permission.java              # Permission enum
│   ├── UserRepository.java          # User data access
│   ├── UserService.java             # User business logic
│   └── UserController.java          # User REST endpoints
│
├── token/                           # Token Domain
│   ├── Token.java                   # Token entity
│   ├── TokenType.java               # Token type enum (BEARER)
│   ├── TokenPurpose.java            # Token purpose enum (ACCESS, REFRESH)
│   └── TokenRepository.java         # Token data access
│
├── auth/                            # Authentication Domain
│   ├── AuthenticationService.java   # Authentication logic
│   ├── AuthenticationController.java # Auth REST endpoints
│   ├── AuthenticationRequest.java   # Login request DTO
│   ├── AuthenticationResponse.java  # Login response DTO
│   └── RegisterRequest.java         # Registration request DTO
│
└── SecurityApplication.java         # Spring Boot main class
```

---

## 📡 API Endpoints

### **Authentication Endpoints**

| Method | Endpoint | Açıklama | Authorization |
|--------|----------|----------|---------------|
| `POST` | `/api/v1/auth/register` | User registration | Public |
| `POST` | `/api/v1/auth/authenticate` | Login | Public |
| `POST` | `/api/v1/auth/refresh-token` | Refresh access token | Refresh Token |
| `POST` | `/api/v1/auth/logout` | Logout | Access Token |

### **User Endpoints**

| Method | Endpoint | Açıklama | Authorization |
|--------|----------|----------|---------------|
| `PATCH` | `/api/v1/users` | Change password | `ROLE_USER` |

### **Admin Endpoints**

| Method | Endpoint | Açıklama | Authorization |
|--------|----------|----------|---------------|
| `GET` | `/api/v1/admin/**` | Admin endpoints | `ROLE_ADMIN` |

### **Management Endpoints**

| Method | Endpoint | Açıklama | Authorization |
|--------|----------|----------|---------------|
| `GET` | `/api/v1/management/**` | Management read | `admin:read` or `management:read` |
| `POST` | `/api/v1/management/**` | Management create | `admin:create` or `management:create` |

---

## 🔐 Güvenlik Notları

### **⚠️ PRODUCTION İÇİN GEREKLİ DEĞİŞİKLİKLER:**

1. **Secret Key Externalize Et:**
   ```yaml
   # application.yml
   application:
     security:
       jwt:
         secret-key: ${JWT_SECRET_KEY} # Environment variable kullan!
   ```

2. **SignatureAlgorithm Güncelle:**
   ```java
   // ❌ DEPRECATED
   .signWith(getSignInKey(), SignatureAlgorithm.HS256)
   
   // ✅ DOĞRU
   .signWith(getSignInKey(), SignatureAlgorithm.HS512)
   ```

3. **Token Expiration Ayarla:**
   ```java
   // Access token: 15-30 dakika (production)
   private static final long ACCESS_TOKEN_EXPIRATION = 1000 * 60 * 30; // 30 dakika
   
   // Refresh token: 7-30 gün
   private static final long REFRESH_TOKEN_EXPIRATION = 1000 * 60 * 60 * 24 * 7; // 7 gün
   ```

4. **Rate Limiting Ekle:**
    - Login endpoint'ine rate limiting ekle (brute-force saldırılarını engelle)

5. **Email Verification Ekle:**
    - User registration sonrası email verification

6. **Password Policy Ekle:**
    - Minimum 8 karakter
    - En az 1 büyük harf, 1 küçük harf, 1 rakam, 1 özel karakter

7. **Audit Logging Ekle:**
    - Login/logout event'lerini logla
    - Failed authentication attempt'leri logla

---

## 🎓 ÖZET

### **Spring Security'nin 4 Temel Bean'i:**

1. **UserDetailsService** → "Kullanıcıyı DB'den nasıl bulacaksın?"
2. **AuthenticationProvider** → "Kullanıcıyı nasıl doğrulayacaksın?"
3. **PasswordEncoder** → "Şifreyi nasıl kontrol edeceksin?"
4. **AuthenticationManager** → "Authentication işlemini kim koordine edecek?"

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

- ✅ **UserDetailsService:** Lambda expression ile implement ediyoruz
- ✅ **DaoAuthenticationProvider:** Spring Security'nin default metotlarını kullanıyoruz
- ✅ **AuthenticationManager:** Provider'ları koordine eder, kendisi authentication yapmaz
- ✅ **Authentication Token ≠ JWT Token:** İkisi farklı şeyler!
- ✅ **Stateless:** Server'da session tutmuyoruz, JWT kullanıyoruz
- ✅ **Token Revocation:** Logout sonrası token'ı DB'de revoke ediyoruz
