# Interview Questions & Answers - Article Management System

This document contains comprehensive questions and answers related to concepts used in the Article Management System project, organized by topic. These questions are commonly asked in Java/Spring Boot interviews.

---

## 📑 Table of Contents

1. [Spring Boot Fundamentals](#spring-boot-fundamentals)
2. [Spring Security & JWT](#spring-security--jwt)
3. [Spring Data JPA](#spring-data-jpa)
4. [RESTful API Design](#restful-api-design)
5. **Transaction Management** - Propagation, Isolation
6. **Exception Handling** - Global handlers, Custom exceptions
7. **Email Integration** - Async, Retry mechanisms
8. **Caching** - Spring Cache, Caffeine
9. **Rate Limiting** - Token bucket algorithm
10. **Docker** - Multi-stage builds, Compose

---

## 🔥 Scenario-Based Questions

### Q51: Your application is slow. How would you debug and optimize?

**Answer:**

**Step 1: Identify Bottleneck**
```bash
# Enable SQL logging
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.format_sql=true
```

**Step 2: Check for N+1 Queries**
```java
// Before (N+1 problem)
List<Article> articles = articleRepository.findAll();
for (Article article : articles) {
    System.out.println(article.getAuthor().getName()); // N queries
}

// After (Single query with JOIN FETCH)
@Query("SELECT a FROM Article a JOIN FETCH a.author")
List<Article> findAllWithAuthors();
```

**Step 3: Add Caching**
```java
@Cacheable("articles")
public Article getArticleById(Long id) {
    return articleRepository.findById(id)
        .orElseThrow(() -> new ResourceNotFoundException("Not found"));
}
```

**Step 4: Database Indexing**
```java
@Index(name = "idx_created_at", columnList = "created_at")
@Index(name = "idx_author_id", columnList = "author_id")
```

**Step 5: Pagination**
```java
// Don't fetch all records at once
Page<Article> articles = articleRepository.findAll(pageable);
```

**Step 6: Connection Pool Tuning**
```properties
spring.datasource.hikari.maximum-pool-size=20
spring.datasource.hikari.minimum-idle=10
```

**Step 7: Async Operations**
```java
@Async
public void sendEmail(String to, String subject) {
    // Don't block main thread
}
```

**Monitoring Tools:**
- Spring Boot Actuator metrics
- Database query analyzer
- JProfiler or VisualVM
- Application logs

---

### Q52: How would you handle a situation where emails are not being delivered?

**Answer:**

**Step 1: Check Email Service Status**
```bash
curl http://localhost:8080/api/health/email
```

**Step 2: Verify Configuration**
```properties
# Check these properties
spring.mail.host=smtp.sendgrid.net
spring.mail.port=587
spring.mail.username=apikey
spring.mail.password=${SENDGRID_API_KEY}
app.email.enabled=true
```

**Step 3: Check Logs**
```bash
# Look for error messages
tail -f logs/application.log | grep "email"
```

**Step 4: Test SendGrid API Key**
```bash
curl -X POST https://api.sendgrid.com/v3/mail/send \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "personalizations": [{
      "to": [{"email": "test@example.com"}]
    }],
    "from": {"email": "noreply@yourdomain.com"},
    "subject": "Test",
    "content": [{"type": "text/plain", "value": "Test"}]
  }'
```

**Step 5: Implement Fallback**
```java
@Service
public class EmailService {
    
    @Async
    @Retryable(maxAttempts = 3, backoff = @Backoff(delay = 2000))
    public void sendEmail(String to, String subject, String content) {
        try {
            mailSender.send(message);
        } catch (MailException e) {
            log.error("Failed to send email", e);
            // Save to database for manual retry
            saveFailedEmail(to, subject, content);
        }
    }
    
    private void saveFailedEmail(String to, String subject, String content) {
        FailedEmail failedEmail = new FailedEmail(to, subject, content);
        failedEmailRepository.save(failedEmail);
    }
}
```

**Step 6: Monitor SendGrid Dashboard**
- Check daily email limits
- Verify sender authentication
- Check bounce/spam rates

---

### Q53: A user reports they can't login. How do you troubleshoot?

**Answer:**

**Possible Issues:**

**1. Account Not Verified**
```java
// Check in database
SELECT email_verified, verification_token_expiry 
FROM users WHERE email = 'user@example.com';

// Solution: Resend verification
POST /api/auth/resend-verification
{"email": "user@example.com"}
```

**2. Account Locked**
```java
// Check lock status
SELECT account_locked, failed_login_attempts, lock_time 
FROM users WHERE email = 'user@example.com';

// Solution: Reset failed attempts
UPDATE users 
SET account_locked = false, 
    failed_login_attempts = 0, 
    lock_time = null 
WHERE email = 'user@example.com';
```

**3. Incorrect Password**
```java
// Check logs
[2024-11-04 10:30:00] WARN - Failed login attempt for user: user@example.com

// Solution: Password reset
POST /api/auth/forgot-password
{"email": "user@example.com"}
```

**4. Token Expired**
```java
// Check JWT expiration
jwt.access-token-expiration=900000  // 15 minutes

// Solution: Use refresh token
POST /api/auth/refresh
{"refreshToken": "..."}
```

**5. Rate Limit Exceeded**
```java
// Check logs
[2024-11-04 10:30:00] WARN - Auth rate limit exceeded for key: 192.168.1.1

// Solution: Wait or increase limit
rate.limit.auth=10  // Increase from 5 to 10
```

**Debug Steps:**
1. Check user exists in database
2. Verify email is verified
3. Check account lock status
4. Review recent login attempts in logs
5. Test with known good credentials
6. Check network/firewall issues

---

### Q54: How would you implement soft delete for articles?

**Answer:**

**Implementation:**

**1. Add deleted field to entity**
```java
@Entity
public class Article {
    
    @Column(name = "deleted")
    private boolean deleted = false;
    
    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;
    
    public void softDelete() {
        this.deleted = true;
        this.deletedAt = LocalDateTime.now();
    }
}
```

**2. Override delete method**
```java
@Service
public class ArticleService {
    
    @Transactional
    public void deleteArticle(Long id, String userEmail) {
        Article article = articleRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Not found"));
        
        // Check ownership
        User user = userRepository.findByEmail(userEmail)
            .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        
        if (!article.getAuthor().getId().equals(user.getId())) {
            throw new ForbiddenException("No permission");
        }
        
        // Soft delete
        article.softDelete();
        articleRepository.save(article);
    }
}
```

**3. Filter queries to exclude deleted**
```java
@Repository
public interface ArticleRepository extends JpaRepository<Article, Long> {
    
    @Query("SELECT a FROM Article a WHERE a.deleted = false")
    List<Article> findAll();
    
    @Query("SELECT a FROM Article a WHERE a.id = :id AND a.deleted = false")
    Optional<Article> findById(Long id);
    
    @Query("SELECT a FROM Article a WHERE a.deleted = false AND " +
           "(LOWER(a.title) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
           "LOWER(a.content) LIKE LOWER(CONCAT('%', :keyword, '%')))")
    Page<Article> searchArticles(String keyword, Pageable pageable);
}
```

**4. Alternative: Use @Where annotation**
```java
@Entity
@Where(clause = "deleted = false")
public class Article {
    // Automatically filters all queries
}
```

**5. Admin endpoint to view deleted**
```java
@RestController
@RequestMapping("/api/admin/articles")
public class AdminArticleController {
    
    @GetMapping("/deleted")
    @PreAuthorize("hasRole('ADMIN')")
    public List<Article> getDeletedArticles() {
        return articleRepository.findAllIncludingDeleted();
    }
    
    @PostMapping("/{id}/restore")
    @PreAuthorize("hasRole('ADMIN')")
    public void restoreArticle(@PathVariable Long id) {
        Article article = articleRepository.findByIdIncludingDeleted(id)
            .orElseThrow(() -> new ResourceNotFoundException("Not found"));
        
        article.setDeleted(false);
        article.setDeletedAt(null);
        articleRepository.save(article);
    }
}
```

**Benefits:**
- Data recovery possible
- Audit trail maintained
- Referential integrity preserved

**Trade-offs:**
- More complex queries
- Database grows larger
- Need periodic cleanup

---

### Q55: How would you implement role-based access control (RBAC)?

**Answer:**

**Current Implementation:**
```java
@Entity
public class User {
    @Enumerated(EnumType.STRING)
    private Role role;  // USER or ADMIN
}
```

**Enhanced RBAC:**

**1. Create Permission System**
```java
public enum Permission {
    // Article permissions
    ARTICLE_READ,
    ARTICLE_CREATE,
    ARTICLE_UPDATE,
    ARTICLE_DELETE,
    
    // User permissions
    USER_READ,
    USER_CREATE,
    USER_UPDATE,
    USER_DELETE,
    
    // Admin permissions
    ADMIN_ACCESS
}

@Entity
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String name;  // ROLE_USER, ROLE_ADMIN, ROLE_MODERATOR
    
    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    private Set<Permission> permissions;
}

@Entity
public class User {
    @ManyToMany(fetch = FetchType.EAGER)
    private Set<Role> roles;
}
```

**2. Update UserDetails Implementation**
```java
@Override
public Collection<? extends GrantedAuthority> getAuthorities() {
    List<GrantedAuthority> authorities = new ArrayList<>();
    
    for (Role role : roles) {
        // Add role
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
        
        // Add permissions
        for (Permission permission : role.getPermissions()) {
            authorities.add(new SimpleGrantedAuthority(permission.name()));
        }
    }
    
    return authorities;
}
```

**3. Use Method Security**
```java
@Configuration
@EnableMethodSecurity
public class SecurityConfig {
}

@RestController
@RequestMapping("/api/articles")
public class ArticleController {
    
    @GetMapping
    @PreAuthorize("hasAuthority('ARTICLE_READ')")
    public List<Article> getAll() {
        // Anyone with ARTICLE_READ permission
    }
    
    @PostMapping
    @PreAuthorize("hasAuthority('ARTICLE_CREATE')")
    public Article create(@RequestBody ArticleRequest request) {
        // Only users with ARTICLE_CREATE permission
    }
    
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ARTICLE_DELETE') or @articleService.isAuthor(#id, authentication.name)")
    public void delete(@PathVariable Long id, Authentication authentication) {
        // Admins or article author
    }
}
```

**4. Custom Permission Evaluator**
```java
@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {
    
    @Override
    public boolean hasPermission(Authentication auth, Object targetDomainObject, Object permission) {
        if (auth == null || !(permission instanceof String)) {
            return false;
        }
        
        String targetType = targetDomainObject.getClass().getSimpleName().toUpperCase();
        return hasPrivilege(auth, targetType, permission.toString());
    }
    
    private boolean hasPrivilege(Authentication auth, String targetType, String permission) {
        return auth.getAuthorities().stream()
            .anyMatch(grantedAuth -> 
                grantedAuth.getAuthority().equals(targetType + "_" + permission)
            );
    }
}
```

**5. Usage Example**
```java
@PreAuthorize("hasPermission(#article, 'UPDATE')")
public Article updateArticle(Article article) {
    // Check if user has UPDATE permission on this article
}
```

---

### Q56: How would you implement audit logging?

**Answer:**

**Implementation:**

**1. Create Audit Entity**
```java
@Entity
@Table(name = "audit_logs")
public class AuditLog {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String entityName;  // Article, User, etc.
    private Long entityId;
    
    @Enumerated(EnumType.STRING)
    private AuditAction action;  // CREATE, UPDATE, DELETE
    
    private String performedBy;
    private LocalDateTime performedAt;
    
    @Column(columnDefinition = "TEXT")
    private String oldValue;
    
    @Column(columnDefinition = "TEXT")
    private String newValue;
    
    private String ipAddress;
}

public enum AuditAction {
    CREATE, UPDATE, DELETE, LOGIN, LOGOUT
}
```

**2. Create Audit Service**
```java
@Service
@RequiredArgsConstructor
public class AuditService {
    
    private final AuditLogRepository auditLogRepository;
    
    @Async
    public void logAction(String entityName, Long entityId, 
                         AuditAction action, String performedBy,
                         Object oldValue, Object newValue,
                         String ipAddress) {
        
        AuditLog log = new AuditLog();
        log.setEntityName(entityName);
        log.setEntityId(entityId);
        log.setAction(action);
        log.setPerformedBy(performedBy);
        log.setPerformedAt(LocalDateTime.now());
        log.setOldValue(toJson(oldValue));
        log.setNewValue(toJson(newValue));
        log.setIpAddress(ipAddress);
        
        auditLogRepository.save(log);
    }
    
    private String toJson(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            return null;
        }
    }
}
```

**3. Use AOP for Automatic Logging**
```java
@Aspect
@Component
@RequiredArgsConstructor
public class AuditAspect {
    
    private final AuditService auditService;
    private final HttpServletRequest request;
    
    @AfterReturning(
        pointcut = "@annotation(auditable)",
        returning = "result"
    )
    public void logAudit(JoinPoint joinPoint, Auditable auditable, Object result) {
        String entityName = auditable.entityName();
        AuditAction action = auditable.action();
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : "anonymous";
        
        String ipAddress = request.getRemoteAddr();
        
        auditService.logAction(
            entityName,
            extractEntityId(result),
            action,
            username,
            null,  // old value
            result,
            ipAddress
        );
    }
}
```

**4. Custom Annotation**
```java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Auditable {
    String entityName();
    AuditAction action();
}
```

**5. Usage in Service**
```java
@Service
public class ArticleService {
    
    @Auditable(entityName = "Article", action = AuditAction.CREATE)
    public ArticleResponse createArticle(ArticleRequest request, String userEmail) {
        // Create article
        Article savedArticle = articleRepository.save(article);
        return mapToResponse(savedArticle);
    }
    
    @Auditable(entityName = "Article", action = AuditAction.UPDATE)
    public ArticleResponse updateArticle(Long id, ArticleRequest request, String userEmail) {
        Article article = findById(id);
        // Update article
        return mapToResponse(updatedArticle);
    }
    
    @Auditable(entityName = "Article", action = AuditAction.DELETE)
    public void deleteArticle(Long id, String userEmail) {
        // Delete article
    }
}
```

**6. Query Audit Logs**
```java
@RestController
@RequestMapping("/api/admin/audit")
@PreAuthorize("hasRole('ADMIN')")
public class AuditController {
    
    @GetMapping
    public Page<AuditLog> getAuditLogs(
        @RequestParam(required = false) String entityName,
        @RequestParam(required = false) AuditAction action,
        @RequestParam(required = false) String performedBy,
        Pageable pageable) {
        
        return auditService.searchLogs(entityName, action, performedBy, pageable);
    }
}
```

---

### Q57: How would you implement multi-tenancy?

**Answer:**

**Approaches:**

**1. Separate Database per Tenant**
```java
@Configuration
public class MultiTenantConfig {
    
    @Bean
    public DataSource dataSource() {
        return new TenantRoutingDataSource();
    }
}

public class TenantRoutingDataSource extends AbstractRoutingDataSource {
    
    @Override
    protected Object determineCurrentLookupKey() {
        return TenantContext.getCurrentTenant();
    }
}

public class TenantContext {
    private static ThreadLocal<String> currentTenant = new ThreadLocal<>();
    
    public static void setCurrentTenant(String tenant) {
        currentTenant.set(tenant);
    }
    
    public static String getCurrentTenant() {
        return currentTenant.get();
    }
}
```

**2. Shared Database with Tenant Column (Discriminator)**
```java
@Entity
@FilterDef(name = "tenantFilter", parameters = @ParamDef(name = "tenantId", type = String.class))
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
public class Article {
    
    @Column(name = "tenant_id")
    private String tenantId;
    
    // Other fields
}

@Component
public class TenantFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        HttpServletRequest req = (HttpServletRequest) request;
        String tenantId = req.getHeader("X-Tenant-ID");
        
        TenantContext.setCurrentTenant(tenantId);
        
        try {
            chain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }
}
```

**3. Separate Schema per Tenant**
```java
@Bean
public DataSource dataSource() {
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl(jdbcUrl);
    config.setSchema(TenantContext.getCurrentTenant());
    return new HikariDataSource(config);
}
```

**Usage:**
```java
@RestController
@RequestMapping("/api/articles")
public class ArticleController {
    
    @GetMapping
    public List<Article> getArticles(@RequestHeader("X-Tenant-ID") String tenantId) {
        TenantContext.setCurrentTenant(tenantId);
        return articleService.getAllArticles();
        // Automatically filtered by tenant
    }
}
```

---

### Q58: How would you implement file upload for articles?

**Answer:**

**Implementation:**

**1. Add Dependency**
```xml
<!-- For file storage -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

**2. Create File Storage Service**
```java
@Service
@Slf4j
public class FileStorageService {
    
    @Value("${file.upload-dir}")
    private String uploadDir;
    
    @PostConstruct
    public void init() {
        try {
            Files.createDirectories(Paths.get(uploadDir));
        } catch (IOException e) {
            throw new RuntimeException("Could not create upload directory");
        }
    }
    
    public String storeFile(MultipartFile file) {
        // Validate file
        if (file.isEmpty()) {
            throw new BadRequestException("File is empty");
        }
        
        // Check file type
        String contentType = file.getContentType();
        if (!isImageFile(contentType)) {
            throw new BadRequestException("Only image files allowed");
        }
        
        // Check file size (5MB limit)
        if (file.getSize() > 5 * 1024 * 1024) {
            throw new BadRequestException("File size exceeds 5MB");
        }
        
        // Generate unique filename
        String originalFilename = StringUtils.cleanPath(file.getOriginalFilename());
        String extension = getFileExtension(originalFilename);
        String filename = UUID.randomUUID().toString() + "." + extension;
        
        try {
            // Save file
            Path targetLocation = Paths.get(uploadDir).resolve(filename);
            Files.copy(file.getInputStream(), targetLocation, StandardCopyOption.REPLACE_EXISTING);
            
            log.info("File stored successfully: {}", filename);
            return filename;
            
        } catch (IOException e) {
            throw new RuntimeException("Failed to store file", e);
        }
    }
    
    public Resource loadFileAsResource(String filename) {
        try {
            Path filePath = Paths.get(uploadDir).resolve(filename).normalize();
            Resource resource = new UrlResource(filePath.toUri());
            
            if (resource.exists()) {
                return resource;
            } else {
                throw new ResourceNotFoundException("File not found: " + filename);
            }
        } catch (MalformedURLException e) {
            throw new ResourceNotFoundException("File not found: " + filename);
        }
    }
    
    public void deleteFile(String filename) {
        try {
            Path filePath = Paths.get(uploadDir).resolve(filename).normalize();
            Files.deleteIfExists(filePath);
        } catch (IOException e) {
            log.error("Failed to delete file: {}", filename, e);
        }
    }
    
    private boolean isImageFile(String contentType) {
        return contentType != null && (
            contentType.equals("image/jpeg") ||
            contentType.equals("image/png") ||
            contentType.equals("image/gif") ||
            contentType.equals("image/webp")
        );
    }
    
    private String getFileExtension(String filename) {
        return filename.substring(filename.lastIndexOf(".") + 1);
    }
}
```

**3. Update Article Entity**
```java
@Entity
public class Article {
    
    @Column(name = "cover_image")
    private String coverImage;  // Stores filename
    
    // Other fields
}
```

**4. Controller Endpoints**
```java
@RestController
@RequestMapping("/api/articles")
@RequiredArgsConstructor
public class ArticleController {
    
    private final ArticleService articleService;
    private final FileStorageService fileStorageService;
    
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ArticleResponse> createArticle(
            @RequestParam("title") String title,
            @RequestParam("content") String content,
            @RequestParam(value = "coverImage", required = false) MultipartFile coverImage,
            Authentication authentication) {
        
        ArticleRequest request = new ArticleRequest(title, content);
        
        // Upload image if provided
        if (coverImage != null && !coverImage.isEmpty()) {
            String filename = fileStorageService.storeFile(coverImage);
            request.setCoverImage(filename);
        }
        
        String userEmail = authentication.getName();
        ArticleResponse article = articleService.createArticle(request, userEmail);
        
        return ResponseEntity.status(HttpStatus.CREATED).body(article);
    }
    
    @GetMapping("/files/{filename:.+}")
    public ResponseEntity<Resource> downloadFile(@PathVariable String filename) {
        Resource resource = fileStorageService.loadFileAsResource(filename);
        
        String contentType = "application/octet-stream";
        
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .header(HttpHeaders.CONTENT_DISPOSITION, 
                       "inline; filename=\"" + resource.getFilename() + "\"")
                .body(resource);
    }
}
```

**5. Configuration**
```properties
# File upload settings
spring.servlet.multipart.enabled=true
spring.servlet.multipart.max-file-size=5MB
spring.servlet.multipart.max-request-size=10MB
file.upload-dir=./uploads
```

**Alternative: Cloud Storage (AWS S3)**
```java
@Service
@RequiredArgsConstructor
public class S3FileStorageService {
    
    private final AmazonS3 s3Client;
    
    @Value("${aws.s3.bucket}")
    private String bucketName;
    
    public String uploadFile(MultipartFile file) {
        String filename = UUID.randomUUID().toString();
        
        try {
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(file.getSize());
            metadata.setContentType(file.getContentType());
            
            s3Client.putObject(
                bucketName,
                filename,
                file.getInputStream(),
                metadata
            );
            
            return s3Client.getUrl(bucketName, filename).toString();
            
        } catch (IOException e) {
            throw new RuntimeException("Failed to upload to S3", e);
        }
    }
}
```

---

### Q59: How would you implement search with Elasticsearch?

**Answer:**

**Setup:**

**1. Add Dependencies**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-elasticsearch</artifactId>
</dependency>
```

**2. Configure Elasticsearch**
```properties
spring.elasticsearch.uris=http://localhost:9200
spring.elasticsearch.username=elastic
spring.elasticsearch.password=changeme
```

**3. Create Document**
```java
@Document(indexName = "articles")
public class ArticleDocument {
    
    @Id
    private String id;
    
    @Field(type = FieldType.Text, analyzer = "standard")
    private String title;
    
    @Field(type = FieldType.Text, analyzer = "standard")
    private String content;
    
    @Field(type = FieldType.Keyword)
    private String authorName;
    
    @Field(type = FieldType.Date)
    private LocalDateTime createdAt;
    
    @Field(type = FieldType.Long)
    private Long viewCount;
}
```

**4. Create Repository**
```java
@Repository
public interface ArticleSearchRepository extends ElasticsearchRepository<ArticleDocument, String> {
    
    List<ArticleDocument> findByTitleContaining(String title);
    
    List<ArticleDocument> findByContentContaining(String content);
    
    @Query("{\"bool\": {\"should\": [" +
           "{\"match\": {\"title\": \"?0\"}}," +
           "{\"match\": {\"content\": \"?0\"}}" +
           "]}}")
    Page<ArticleDocument> searchByTitleOrContent(String keyword, Pageable pageable);
}
```

**5. Sync Service**
```java
@Service
@RequiredArgsConstructor
public class ArticleSearchService {
    
    private final ArticleRepository articleRepository;
    private final ArticleSearchRepository searchRepository;
    
    public void indexArticle(Article article) {
        ArticleDocument document = new ArticleDocument();
        document.setId(article.getId().toString());
        document.setTitle(article.getTitle());
        document.setContent(article.getContent());
        document.setAuthorName(article.getAuthorName());
        document.setCreatedAt(article.getCreatedAt());
        document.setViewCount(article.getViewCount());
        
        searchRepository.save(document);
    }
    
    public void deleteFromIndex(Long articleId) {
        searchRepository.deleteById(articleId.toString());
    }
    
    public Page<ArticleDocument> search(String keyword, Pageable pageable) {
        return searchRepository.searchByTitleOrContent(keyword, pageable);
    }
    
    @PostConstruct
    public void reindexAll() {
        // Initial bulk indexing
        List<Article> articles = articleRepository.findAll();
        articles.forEach(this::indexArticle);
    }
}
```

**6. Update Service Methods**
```java
@Service
public class ArticleService {
    
    private final ArticleSearchService searchService;
    
    public ArticleResponse createArticle(ArticleRequest request, String userEmail) {
        Article article = // create article
        Article saved = articleRepository.save(article);
        
        // Index in Elasticsearch
        searchService.indexArticle(saved);
        
        return mapToResponse(saved);
    }
    
    public void deleteArticle(Long id, String userEmail) {
        // delete from database
        articleRepository.delete(article);
        
        // Remove from index
        searchService.deleteFromIndex(id);
    }
}
```

**Benefits:**
- Full-text search
- Fuzzy matching
- Relevance scoring
- Fast search on large datasets
- Advanced search features (autocomplete, suggestions)

---

### Q60: What monitoring and observability would you add?

**Answer:**

**1. Spring Boot Actuator**
```properties
management.endpoints.web.exposure.include=health,metrics,prometheus
management.endpoint.health.show-details=always
management.metrics.export.prometheus.enabled=true
```

**2. Custom Metrics**
```java
@Service
@RequiredArgsConstructor
public class ArticleService {
    
    private final MeterRegistry meterRegistry;
    
    public ArticleResponse createArticle(ArticleRequest request, String userEmail) {
        Timer.Sample sample = Timer.start(meterRegistry);
        
        try {
            // Create article
            Article article = // ...
            
            // Record success metric
            meterRegistry.counter("article.created", "status", "success").increment();
            
            return mapToResponse(article);
            
        } catch (Exception e) {
            // Record failure metric
            meterRegistry.counter("article.created", "status", "failure").increment();
            throw e;
            
        } finally {
            sample.stop(meterRegistry.timer("article.creation.time"));
        }
    }
}
```

**3. Structured Logging**
```java
@Slf4j
@Service
public class ArticleService {
    
    public ArticleResponse createArticle(ArticleRequest request, String userEmail) {
        log.info("Creating article - user: {}, title: {}", 
                 userEmail, request.getTitle());
        
        try {
            Article article = // create article
            
            log.info("Article created successfully - id: {}, user: {}", 
                     article.getId(), userEmail);
            
            return mapToResponse(article);
            
        } catch (Exception e) {
            log.error("Failed to create article - user: {}, error: {}", 
                      userEmail, e.getMessage(), e);
            throw e;
        }
    }
}
```

**4. Logback Configuration**
```xml
<!-- logback-spring.xml -->
<configuration>
    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/application.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>logs/application-%d{yyyy-MM-dd}.%i.log</fileNamePattern>
            <maxHistory>30</maxHistory>
            <maxFileSize>10MB</maxFileSize>
        </rollingPolicy>
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    
    <appender name="JSON" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/application.json</file>
        <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
    </appender>
    
    <root level="INFO">
        <appender-ref ref="FILE"/>
        <appender-ref ref="JSON"/>
    </root>
</configuration>
```

**5. Health Indicators**
```java
@Component
public class DatabaseHealthIndicator implements HealthIndicator {
    
    @Autowired
    private DataSource dataSource;
    
    @Override
    public Health health() {
        try (Connection conn = dataSource.getConnection()) {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT 1");
            
            return Health.up()
                    .withDetail("database", "PostgreSQL")
                    .withDetail("status", "Connected")
                    .withDetail("validationQuery", "SELECT 1")
                    .build();
                    
        } catch (SQLException e) {
            return Health.down()
                    .withDetail("error", e.getMessage())
                    .withException(e)
                    .build();
        }
    }
}

@Component
public class EmailServiceHealthIndicator implements HealthIndicator {
    
    @Autowired
    private JavaMailSender mailSender;
    
    @Value("${app.email.enabled}")
    private boolean emailEnabled;
    
    @Override
    public Health health() {
        if (!emailEnabled) {
            return Health.up()
                    .withDetail("status", "Disabled")
                    .build();
        }
        
        try {
            mailSender.testConnection();
            return Health.up()
                    .withDetail("provider", "SendGrid")
                    .withDetail("status", "Connected")
                    .build();
        } catch (Exception e) {
            return Health.down()
                    .withDetail("error", e.getMessage())
                    .build();
        }
    }
}
```

**6. Prometheus Integration**
```properties
# application.properties
management.metrics.export.prometheus.enabled=true
management.metrics.tags.application=${spring.application.name}
management.metrics.tags.environment=${spring.profiles.active}
```

**7. Alert Configuration (AlertManager)**
```yaml
# alertmanager.yml
groups:
  - name: article-app-alerts
    rules:
      - alert: HighErrorRate
        expr: rate(article_created{status="failure"}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High article creation failure rate"
          
      - alert: DatabaseDown
        expr: up{job="database"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database is down"
          
      - alert: HighResponseTime
        expr: histogram_quantile(0.95, article_creation_time) > 5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "95th percentile response time > 5s"
```

**8. Distributed Tracing (Zipkin/Jaeger)**
```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-sleuth</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-sleuth-zipkin</artifactId>
</dependency>
```

```properties
spring.zipkin.base-url=http://localhost:9411
spring.sleuth.sampler.probability=1.0
```

**Benefits:**
- **Metrics:** Track performance, errors, throughput
- **Logging:** Debug issues, audit trail
- **Health Checks:** Monitor service status
- **Tracing:** Follow requests across services
- **Alerts:** Proactive issue detection

---

## 🎓 Learning Path Recommendations

### Beginner Level (Foundation)
1. **Java Fundamentals**
   - OOP concepts
   - Collections framework
   - Exception handling
   - Lambda expressions

2. **Spring Core**
   - Dependency Injection
   - Bean lifecycle
   - Configuration management

3. **Spring Boot Basics**
   - Auto-configuration
   - Starters
   - Application properties

4. **REST API Basics**
   - HTTP methods
   - Status codes
   - JSON serialization

### Intermediate Level (This Project)
1. **Spring Security**
   - Authentication mechanisms
   - JWT implementation
   - Authorization strategies

2. **Spring Data JPA**
   - Entity relationships
   - Query methods
   - Transaction management

3. **Database Design**
   - Normalization
   - Indexing
   - Schema design

4. **Testing**
   - Unit tests (JUnit)
   - Integration tests
   - Mockito

### Advanced Level
1. **Microservices Architecture**
   - Service discovery
   - API Gateway
   - Circuit breakers

2. **Message Queues**
   - RabbitMQ/Kafka
   - Event-driven architecture
   - Async processing

3. **Cloud Deployment**
   - Docker orchestration
   - Kubernetes
   - CI/CD pipelines

4. **Advanced Patterns**
   - CQRS
   - Event Sourcing
   - Saga pattern

---

## 📖 Recommended Resources

### Books
1. **"Spring in Action"** by Craig Walls
2. **"Spring Boot in Practice"** by Somnath Musib
3. **"Effective Java"** by Joshua Bloch
4. **"Designing Data-Intensive Applications"** by Martin Kleppmann

### Online Courses
1. **Baeldung** - Spring Boot tutorials
2. **Spring Academy** - Official Spring courses
3. **Udemy** - Spring Boot microservices
4. **Pluralsight** - Spring Framework path

### Documentation
1. **Spring Boot Reference Documentation**
2. **Spring Security Reference**
3. **Spring Data JPA Documentation**
4. **PostgreSQL Documentation**

### Practice Platforms
1. **GitHub** - Contribute to open source
2. **LeetCode** - Algorithm practice
3. **HackerRank** - Java challenges
4. **Spring Initializr** - Create projects

---

## 🔑 Key Takeaways

### Architecture Principles
1. **Separation of Concerns** - Controllers, Services, Repositories
2. **Single Responsibility** - Each class has one job
3. **Dependency Inversion** - Depend on abstractions
4. **Open/Closed Principle** - Open for extension, closed for modification

### Best Practices Implemented
1. ✅ RESTful API design
2. ✅ JWT-based authentication
3. ✅ Global exception handling
4. ✅ Input validation
5. ✅ Async email processing
6. ✅ Rate limiting
7. ✅ Caching
8. ✅ Connection pooling
9. ✅ Transaction management
10. ✅ Database indexing

### Production Readiness Checklist
- [x] Authentication & Authorization
- [x] Error handling
- [x] Logging
- [x] Monitoring (Actuator)
- [x] Rate limiting
- [x] Input validation
- [x] Database optimization
- [x] Email notifications
- [x] Docker support
- [x] Environment configuration
- [ ] Integration tests
- [ ] Load testing
- [ ] Security audit
- [ ] Performance profiling
- [ ] Documentation

---

## 💡 Interview Preparation Tips

### Before the Interview

**1. Review Your Project Thoroughly**
- Understand every component
- Know why you made certain decisions
- Be ready to explain trade-offs

**2. Practice Common Questions**
- Explain the flow from request to response
- Describe how authentication works
- Discuss database schema design

**3. Prepare Examples**
```
Interviewer: "How do you handle errors?"
You: "In my Article Management project, I implemented a global 
exception handler using @RestControllerAdvice. For example, 
when a user tries to access a non-existent article, we throw 
ResourceNotFoundException which is caught by the handler and 
returns a 404 status with a custom error response."
```

**4. Be Ready to Code**
- Write a simple REST endpoint
- Implement a repository method
- Create a DTO

### During the Interview

**1. Ask Clarifying Questions**
```
Interviewer: "How would you implement caching?"
You: "Are you asking about in-memory caching like Caffeine, 
or distributed caching like Redis? And what's the use case - 
read-heavy operations or something specific?"
```

**2. Think Aloud**
- Explain your thought process
- Discuss alternatives
- Mention trade-offs

**3. Draw Diagrams**
- Architecture diagrams
- Database schemas
- Request flow

**4. Admit What You Don't Know**
```
"I haven't worked with that specific technology, but I've used 
something similar. For example, I've worked with Caffeine for 
caching in my project, which is similar to Redis in concept."
```

### After the Interview

**1. Follow Up**
- Thank you email
- Mention specific topics discussed
- Express continued interest

**2. Learn from Experience**
- Note questions you struggled with
- Study those topics
- Practice more

---

## 🚀 Next Steps to Enhance This Project

### Short Term (1-2 weeks)
1. **Add Comprehensive Tests**
   - Unit tests for services
   - Integration tests for controllers
   - Test coverage > 80%

2. **Implement Swagger/OpenAPI**
   - API documentation
   - Interactive testing UI

3. **Add More Validation**
   - Custom validators
   - Business rule validation

### Medium Term (1 month)
1. **Implement Advanced Features**
   - Article tags/categories
   - Comments system
   - Like/favorite functionality
   - User profiles

2. **Enhance Security**
   - 2FA authentication
   - OAuth2 integration
   - IP whitelisting

3. **Add Monitoring**
   - ELK stack integration
   - Prometheus + Grafana
   - Custom dashboards

### Long Term (2-3 months)
1. **Microservices Architecture**
   - Split into separate services
   - Service discovery (Eureka)
   - API Gateway

2. **Advanced Search**
   - Elasticsearch integration
   - Full-text search
   - Search suggestions

3. **Scalability**
   - Redis for caching
   - Message queue (RabbitMQ)
   - Load balancing

---

## 📝 Common Mistakes to Avoid

### 1. Not Understanding Your Own Code
❌ Bad: "I just copied this from Stack Overflow"
✅ Good: "I implemented JWT authentication because it's stateless and scalable"

### 2. Overcomplicating Simple Questions
❌ Bad: Long, convoluted explanations
✅ Good: Clear, concise answers with examples

### 3. Not Asking Questions
❌ Bad: Assuming you understand everything
✅ Good: "Could you clarify what you mean by..."

### 4. Not Admitting Gaps in Knowledge
❌ Bad: Making up answers
✅ Good: "I'm not familiar with that, but I can learn it quickly"

### 5. Not Discussing Trade-offs
❌ Bad: "This is the best approach"
✅ Good: "I chose this because... but it has these trade-offs..."

---

## 🎯 Final Exam: Self-Assessment Questions

Test your understanding:

1. ✓ Can you explain the entire authentication flow in the project?
2. ✓ Can you draw the database schema from memory?
3. ✓ Can you explain how rate limiting works?
4. ✓ Can you describe the email sending process?
5. ✓ Can you explain how transactions work?
6. ✓ Can you discuss the caching strategy?
7. ✓ Can you explain the exception handling approach?
8. ✓ Can you describe the pagination implementation?
9. ✓ Can you explain the JWT token lifecycle?
10. ✓ Can you discuss the Docker deployment strategy?

**If you can answer 8-10:** You're ready for interviews! 🎉
**If you can answer 5-7:** Review the topics you're uncertain about
**If you can answer < 5:** Spend more time understanding the project

---

## 🌟 Success Stories Format

When discussing your project in interviews:

### The STAR Method

**Situation:** "In my Article Management project, I needed to implement secure authentication..."

**Task:** "The challenge was to create a stateless authentication system that scales well..."

**Action:** "I implemented JWT-based authentication with separate access and refresh tokens..."

**Result:** "This provided secure, scalable authentication with automatic token refresh, reducing login friction by 70%"

---

## 📚 Glossary of Terms

**API (Application Programming Interface)** - Interface for applications to communicate

**JWT (JSON Web Token)** - Compact token format for authentication

**REST (Representational State Transfer)** - Architectural style for APIs

**JPA (Java Persistence API)** - Java specification for ORM

**ORM (Object-Relational Mapping)** - Map objects to database tables

**DTO (Data Transfer Object)** - Object for transferring data between layers

**CRUD (Create, Read, Update, Delete)** - Basic database operations

**CORS (Cross-Origin Resource Sharing)** - Security feature for cross-domain requests

**CSRF (Cross-Site Request Forgery)** - Type of security attack

**DI (Dependency Injection)** - Design pattern for loose coupling

**IoC (Inversion of Control)** - Design principle where framework controls flow

**ACID (Atomicity, Consistency, Isolation, Durability)** - Database transaction properties

**SQL (Structured Query Language)** - Language for database queries

**JPQL (Java Persistence Query Language)** - Query language for JPA

**BCrypt** - Password hashing algorithm

**SMTP (Simple Mail Transfer Protocol)** - Protocol for email transmission

**HTTP (Hypertext Transfer Protocol)** - Protocol for web communication

**SSL/TLS (Secure Sockets Layer/Transport Layer Security)** - Encryption protocols

**JSON (JavaScript Object Notation)** - Data interchange format

**XML (eXtensible Markup Language)** - Markup language for data

---

## 🎓 Conclusion

This Article Management System project covers essential concepts for modern backend development:

✅ **Spring Boot** - Framework fundamentals
✅ **REST APIs** - Best practices and design
✅ **Security** - Authentication and authorization
✅ **Database** - Design and optimization
✅ **Email** - Integration and async processing
✅ **Performance** - Caching and connection pooling
✅ **Scalability** - Rate limiting and Docker

By understanding these concepts deeply, you'll be well-prepared for:
- Backend developer interviews
- Real-world project development
- System design discussions
- Technical decision making

**Remember:** The goal isn't to memorize answers, but to understand concepts deeply enough to explain them clearly and apply them appropriately.

**Good luck with your interviews! 🚀**

---

**Last Updated:** November 2024
**Project Version:** 1.0.0
**Maintained by:** Aryan [Exception Handling](#exception-handling)
6. [Email Integration](#email-integration)
7. [Caching & Performance](#caching--performance)
8. [Rate Limiting](#rate-limiting)
9. [Database Design](#database-design)
10. [Docker & Deployment](#docker--deployment)
11. [Design Patterns](#design-patterns)
12. [Advanced Topics](#advanced-topics)

---

## 1. Spring Boot Fundamentals

### Q1: What is Spring Boot and why use it?

**Answer:**
Spring Boot is an opinionated framework built on top of the Spring Framework that simplifies the setup and development of Spring applications.

**Key Benefits:**
- **Auto-configuration:** Automatically configures Spring and third-party libraries
- **Embedded servers:** Tomcat, Jetty, or Undertow included
- **Production-ready features:** Actuator for monitoring, health checks
- **Minimal configuration:** Convention over configuration approach
- **Starter dependencies:** Pre-configured dependency sets

**Example from project:**
```java
@SpringBootApplication
public class ArticleMsBackendApplication {
    public static void main(String[] args) {
        SpringApplication.run(ArticleMsBackendApplication.class, args);
    }
}
```

---

### Q2: Explain Dependency Injection in Spring.

**Answer:**
Dependency Injection (DI) is a design pattern where objects receive their dependencies from an external source rather than creating them.

**Types:**
- **B-Tree:** Default, general purpose
- **Hash:** Equality comparisons
- **Full-text:** Text search

---

## 8. Rate Limiting

### Q30: What is rate limiting and why is it important?

**Answer:**
Rate limiting restricts the number of requests a client can make in a time window.

**Why Rate Limit?**
- **DoS Protection:** Prevent abuse
- **Fair Usage:** Ensure resources for all users
- **Cost Control:** Limit API usage
- **Performance:** Prevent overload

**Attack Scenario Without Rate Limiting:**
```
Attacker sends 10,000 requests/second
→ Server overwhelmed
→ Legitimate users cannot access
→ Service down
```

**Project Implementation - Token Bucket Algorithm:**
```java
@Service
public class RateLimitService {
    
    public Bucket resolveBucket(String key) {
        return cache.computeIfAbsent(key, k -> createBucket(100, 1));
    }
    
    private Bucket createBucket(long capacity, int minutes) {
        Bandwidth limit = Bandwidth.classic(
            capacity,  // 100 tokens
            Refill.intervally(capacity, Duration.ofMinutes(minutes))
        );
        return Bucket.builder().addLimit(limit).build();
    }
    
    public void checkRateLimit(String key) {
        Bucket bucket = resolveBucket(key);
        if (!bucket.tryConsume(1)) {
            throw new RateLimitExceededException(
                "Too many requests. Please try again later."
            );
        }
    }
}
```

---

### Q31: Explain Token Bucket Algorithm.

**Answer:**
Token Bucket is a rate limiting algorithm.

**How it works:**
1. **Bucket:** Has maximum capacity (100 tokens)
2. **Refill:** Tokens added at fixed rate (100 per minute)
3. **Consume:** Each request consumes 1 token
4. **Reject:** If no tokens available, request rejected

**Visual:**
```
Time: 0s    Bucket: [100 tokens]
Request 1   Bucket: [99 tokens]   ✅ Allowed
Request 2   Bucket: [98 tokens]   ✅ Allowed
...
Request 100 Bucket: [0 tokens]    ✅ Allowed
Request 101 Bucket: [0 tokens]    ❌ Rejected (429)

Time: 60s   Bucket: [100 tokens]  (Refilled)
```

**Benefits:**
- **Burst handling:** Allows short bursts
- **Smooth:** Predictable behavior
- **Fair:** Tokens distributed evenly

**Alternative Algorithms:**
- **Fixed Window:** Simple, but burst at window edge
- **Sliding Window:** More accurate, complex
- **Leaky Bucket:** Constant rate, no bursts

---

### Q32: How do you implement different rate limits for different endpoints?

**Answer:**
Use separate buckets for different endpoint categories.

**Project Implementation:**
```java
@Component
@RequiredArgsConstructor
public class RateLimitInterceptor implements HandlerInterceptor {
    
    private final RateLimitService rateLimitService;
    
    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) {
        
        String clientIp = getClientIP(request);
        String path = request.getRequestURI();
        
        if (path.startsWith("/api/auth/login") ||
            path.startsWith("/api/auth/register")) {
            // Stricter limit for auth endpoints
            rateLimitService.checkAuthRateLimit(clientIp);
        } else {
            // General limit for other endpoints
            rateLimitService.checkRateLimit(clientIp);
        }
        
        return true;
    }
}
```

**Rate Limits:**
- **Auth endpoints:** 5 requests/minute (prevent brute force)
- **General endpoints:** 100 requests/minute (normal usage)

**Identifying Clients:**
```java
private String getClientIP(HttpServletRequest request) {
    String xfHeader = request.getHeader("X-Forwarded-For");
    if (xfHeader == null) {
        return request.getRemoteAddr();
    }
    return xfHeader.split(",")[0];  // First IP in chain
}
```

---

## 9. Database Design

### Q33: Explain database normalization in your schema.

**Answer:**
Normalization reduces data redundancy and improves integrity.

**Project Schema Analysis:**

**Users Table (3NF):**
```sql
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(100) NOT NULL,
    -- All columns depend on primary key
    -- No transitive dependencies
);
```

**Articles Table (3NF):**
```sql
CREATE TABLE articles (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    content TEXT NOT NULL,
    author_id BIGINT NOT NULL,
    author_name VARCHAR(100) NOT NULL,  -- Denormalization!
    FOREIGN KEY (author_id) REFERENCES users(id)
);
```

**Denormalization Decision:**
- Storing `author_name` duplicates data
- **Why?** Avoid JOIN on every article fetch
- **Trade-off:** Storage vs Performance

**Normal Forms:**
- **1NF:** Atomic values, no repeating groups ✅
- **2NF:** No partial dependencies ✅
- **3NF:** No transitive dependencies ✅

---

### Q34: What are database constraints and why use them?

**Answer:**
Constraints enforce data integrity rules.

**Project Constraints:**

**1. Primary Key:**
```sql
id BIGSERIAL PRIMARY KEY
```
- Uniquely identifies each row
- Cannot be NULL
- Indexed automatically

**2. Foreign Key:**
```sql
FOREIGN KEY (author_id) REFERENCES users(id)
```
- Maintains referential integrity
- Prevents orphaned records
- Cascade options available

**3. Unique:**
```sql
email VARCHAR(100) UNIQUE NOT NULL
```
- Ensures no duplicates
- Useful for email, username

**4. Not Null:**
```sql
title VARCHAR(200) NOT NULL
```
- Prevents NULL values
- Ensures required data exists

**5. Check (Custom):**
```sql
CHECK (view_count >= 0)
```
- Custom business rules
- Validates data before insert/update

**Benefits:**
- **Data Quality:** Invalid data rejected at database level
- **Performance:** Some constraints create indexes
- **Documentation:** Schema is self-documenting

---

### Q35: Explain cascade operations in JPA.

**Answer:**
Cascade operations propagate changes from parent to child entities.

**Project Example:**
```java
@Entity
public class User {
    
    @OneToMany(
        mappedBy = "author",
        cascade = CascadeType.ALL,  // All operations cascade
        orphanRemoval = true        // Delete orphaned articles
    )
    private List<Article> articles;
}
```

**Cascade Types:**

**1. CascadeType.PERSIST**
```java
User user = new User();
Article article = new Article();
user.addArticle(article);
entityManager.persist(user);  // Article also persisted
```

**2. CascadeType.REMOVE**
```java
entityManager.remove(user);  // All user's articles deleted
```

**3. CascadeType.MERGE**
```java
User detachedUser = // from somewhere
entityManager.merge(detachedUser);  // Articles also merged
```

**4. CascadeType.ALL**
- Combines all cascade types
- Use carefully - can have unintended effects

**5. orphanRemoval = true**
```java
user.getArticles().remove(article);
entityManager.persist(user);  // Article deleted from DB
```

---

## 10. Docker & Deployment

### Q36: Explain multi-stage Docker builds.

**Answer:**
Multi-stage builds reduce final image size.

**Project Dockerfile:**
```dockerfile
# Stage 1: Build
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /app

COPY .mvn/ .mvn
COPY mvnw pom.xml ./
RUN ./mvnw dependency:resolve -B

COPY src ./src
RUN ./mvnw clean package -DskipTests -B

# Stage 2: Runtime
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```

**Benefits:**
- **Smaller Image:** Only JRE in final image (not JDK)
- **Security:** Fewer components = less attack surface
- **Speed:** Faster deployment and startup

**Size Comparison:**
- Single-stage (with JDK): ~450 MB
- Multi-stage (with JRE): ~200 MB

---

### Q37: How do you manage environment variables in Docker?

**Answer:**
Environment variables configure application without code changes.

**1. Dockerfile ENV:**
```dockerfile
ENV JAVA_OPTS="-Xmx512m"
```

**2. Docker Run:**
```bash
docker run -e PGHOST=postgres -e PGPORT=5432 app
```

**3. Docker Compose:**
```yaml
services:
  app:
    build: .
    environment:
      PGHOST: postgres
      PGPORT: 5432
      PGDATABASE: articledb
      JWT_SECRET: ${JWT_SECRET}  # From host environment
      SENDGRID_API_KEY: ${SENDGRID_API_KEY}
```

**4. .env File:**
```bash
# .env
JWT_SECRET=your-secret-key
SENDGRID_API_KEY=your-api-key
```

**Best Practices:**
- **Never commit secrets** to version control
- Use `.env` files locally
- Use secret management in production (AWS Secrets Manager, HashiCorp Vault)
- Validate required variables at startup

---

### Q38: What is Docker Compose and when to use it?

**Answer:**
Docker Compose orchestrates multi-container applications.

**Project docker-compose.yml:**
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: articledb
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      PGHOST: postgres
      PGPORT: 5432
    depends_on:
      postgres:
        condition: service_healthy

volumes:
  postgres_data:
```

**Benefits:**
- **Single Command:** `docker-compose up -d`
- **Networking:** Automatic service discovery
- **Dependencies:** Start services in order
- **Volumes:** Persistent data storage

**Commands:**
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f app

# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

---

## 11. Design Patterns

### Q39: What design patterns are used in the project?

**Answer:**

**1. Repository Pattern**
```java
@Repository
public interface ArticleRepository extends JpaRepository<Article, Long> {
    // Abstracts data access logic
}
```
- **Purpose:** Separates data access from business logic
- **Benefits:** Easy to test, change data source

**2. Service Layer Pattern**
```java
@Service
public class ArticleService {
    private final ArticleRepository articleRepository;
    // Business logic here
}
```
- **Purpose:** Encapsulates business logic
- **Benefits:** Reusable, testable

**3. DTO (Data Transfer Object) Pattern**
```java
public class ArticleRequest {
    private String title;
    private String content;
}

public class ArticleResponse {
    private Long id;
    private String title;
    // ... more fields
}
```
- **Purpose:** Transfer data between layers
- **Benefits:** Decouple internal model from API

**4. Builder Pattern**
```java
Article article = Article.builder()
    .title("Title")
    .content("Content")
    .author(user)
    .build();
```
- **Purpose:** Construct complex objects
- **Benefits:** Readable, immutable objects

**5. Strategy Pattern**
```java
// Different authentication strategies
public interface AuthenticationProvider {
    Authentication authenticate(Authentication auth);
}
```

**6. Template Method Pattern**
```java
public abstract class OncePerRequestFilter {
    public final void doFilter(...) {
        // Template method
        doFilterInternal(...);  // Hook method
    }
    
    protected abstract void doFilterInternal(...);
}
```

**7. Singleton Pattern**
```java
@Service  // Spring creates single instance
public class EmailService {
}
```

---

### Q40: Explain Dependency Injection as a design pattern.

**Answer:**
Dependency Injection (DI) is an implementation of Inversion of Control (IoC).

**Without DI:**
```java
public class ArticleService {
    private ArticleRepository repository = new ArticleRepository();
    // Tight coupling, hard to test
}
```

**With DI:**
```java
@Service
@RequiredArgsConstructor
public class ArticleService {
    private final ArticleRepository repository;
    // Loose coupling, easy to test
}
```

**Types:**

**1. Constructor Injection (Recommended)**
```java
@Service
public class ArticleService {
    private final ArticleRepository repository;
    
    public ArticleService(ArticleRepository repository) {
        this.repository = repository;
    }
}
```
**Benefits:**
- Immutable dependencies
- Required dependencies clear
- Easy to test

**2. Setter Injection**
```java
@Service
public class ArticleService {
    private ArticleRepository repository;
    
    @Autowired
    public void setRepository(ArticleRepository repository) {
        this.repository = repository;
    }
}
```
**Use case:** Optional dependencies

**3. Field Injection (Not Recommended)**
```java
@Service
public class ArticleService {
    @Autowired
    private ArticleRepository repository;
}
```
**Problems:**
- Cannot create immutable fields
- Hard to test
- Hidden dependencies

---

## 12. Advanced Topics

### Q41: What is the difference between @Component, @Service, and @Repository?

**Answer:**
All are stereotype annotations for Spring beans.

**Hierarchy:**
```
@Component (Generic)
    ↓
    @Service (Business Logic)
    @Repository (Data Access)
    @Controller (Web)
    @RestController (REST API)
```

**@Component:**
```java
@Component
public class EmailValidator {
    // Generic Spring bean
}
```
- Generic stereotype
- For any Spring-managed component

**@Service:**
```java
@Service
public class ArticleService {
    // Business logic layer
}
```
- Indicates service layer
- No additional functionality (yet)
- Semantic meaning for developers

**@Repository:**
```java
@Repository
public interface ArticleRepository extends JpaRepository<Article, Long> {
    // Data access layer
}
```
- Exception translation (SQLException → DataAccessException)
- Semantic meaning for data access

**When to use:**
- **@Repository:** Data access classes/interfaces
- **@Service:** Business logic classes
- **@Component:** Everything else (utilities, helpers)

---

### Q42: Explain @Transactional propagation types.

**Answer:**
Propagation defines how transactions relate to each other.

**1. REQUIRED (Default)**
```java
@Transactional(propagation = Propagation.REQUIRED)
public void method1() {
    method2();
}

@Transactional(propagation = Propagation.REQUIRED)
public void method2() {
    // Uses same transaction as method1
}
```
- Join existing transaction or create new

**2. REQUIRES_NEW**
```java
@Transactional(propagation = Propagation.REQUIRES_NEW)
public void logActivity() {
    // Always creates new transaction
    // Independent of outer transaction
}
```
- Always create new transaction
- Suspend current transaction

**Use case:** Audit logging (log even if main transaction fails)

**3. NESTED**
```java
@Transactional(propagation = Propagation.NESTED)
public void processItem() {
    // Nested within parent transaction
    // Can rollback independently
}
```
- Nested transaction (savepoint)
- Rollback doesn't affect parent

**4. MANDATORY**
```java
@Transactional(propagation = Propagation.MANDATORY)
public void method() {
    // Must be called within transaction
    // Throws exception if no transaction exists
}
```

**5. SUPPORTS**
```java
@Transactional(propagation = Propagation.SUPPORTS)
public void method() {
    // Join transaction if exists
    // Execute non-transactionally otherwise
}
```

**6. NOT_SUPPORTED**
```java
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public void method() {
    // Always execute non-transactionally
    // Suspend current transaction
}
```

**7. NEVER**
```java
@Transactional(propagation = Propagation.NEVER)
public void method() {
    // Throw exception if transaction exists
}
```

---

### Q43: What are the differences between @Mock, @MockBean, and @InjectMocks?

**Answer:**
These annotations are used in testing.

**@Mock (Mockito)**
```java
@ExtendWith(MockitoExtension.class)
public class ArticleServiceTest {
    
    @Mock
    private ArticleRepository articleRepository;
    
    @InjectMocks
    private ArticleService articleService;
    
    @Test
    void testGetArticle() {
        when(articleRepository.findById(1L))
            .thenReturn(Optional.of(article));
        
        Article result = articleService.getArticleById(1L);
        assertNotNull(result);
    }
}
```
- Pure Mockito mock
- Unit testing
- No Spring context

**@MockBean (Spring Boot Test)**
```java
@SpringBootTest
public class ArticleControllerIntegrationTest {
    
    @MockBean
    private ArticleService articleService;
    
    @Autowired
    private MockMvc mockMvc;
    
    @Test
    void testGetArticle() throws Exception {
        mockMvc.perform(get("/api/articles/1"))
               .andExpect(status().isOk());
    }
}
```
- Spring Boot mock
- Integration testing
- Replaces bean in Spring context

**@InjectMocks**
```java
@Mock
private ArticleRepository repository;

@InjectMocks
private ArticleService service;  // Injects repository mock
```
- Injects mocks into test subject
- Constructor/setter/field injection

**Comparison:**

| Annotation | Framework | Spring Context | Use Case |
|-----------|-----------|----------------|----------|
| @Mock | Mockito | No | Unit tests |
| @MockBean | Spring Boot | Yes | Integration tests |
| @InjectMocks | Mockito | No | Inject mocks |

---

### Q44: Explain lazy loading vs eager loading in JPA.

**Answer:**
Loading strategies for entity relationships.

**Lazy Loading (FetchType.LAZY)**
```java
@Entity
public class Article {
    @ManyToOne(fetch = FetchType.LAZY)
    private User author;  // Loaded only when accessed
}

// Usage
Article article = articleRepository.findById(1L);
// Author NOT loaded yet

String name = article.getAuthor().getName();
// NOW author is loaded (separate query)
```

**Eager Loading (FetchType.EAGER)**
```java
@Entity
public class Article {
    @ManyToOne(fetch = FetchType.EAGER)
    private User author;  // Loaded immediately with article
}

// Usage
Article article = articleRepository.findById(1L);
// Author already loaded (single JOIN query)
```

**Defaults:**
- `@OneToMany`: LAZY
- `@ManyToMany`: LAZY
- `@ManyToOne`: EAGER
- `@OneToOne`: EAGER

**Best Practices:**
1. **Default to LAZY:** Avoid unnecessary queries
2. **Use JOIN FETCH when needed:**
```java
@Query("SELECT a FROM Article a JOIN FETCH a.author WHERE a.id = :id")
Article findByIdWithAuthor(Long id);
```

**LazyInitializationException:**
```java
@Transactional
public ArticleResponse getArticle(Long id) {
    Article article = articleRepository.findById(id);
    // Access author within transaction
    String name = article.getAuthor().getName();
    return toResponse(article);
}
// Transaction closed, author no longer accessible
```

**Solution:** Fetch within transaction or use DTO projection.

---

### Q45: What is the difference between save() and saveAndFlush()?

**Answer:**

**save()**
```java
Article article = new Article();
articleRepository.save(article);
// Changes stored in memory (persistence context)
// Not yet in database
```
- Stores entity in persistence context
- SQL executed at flush time or transaction commit
- Batch operations possible

**saveAndFlush()**
```java
Article article = new Article();
articleRepository.saveAndFlush(article);
// Changes immediately written to database
// Synchronizes persistence context
```
- Immediately flushes to database
- Forces SQL execution
- Returns entity with generated ID

**When to use saveAndFlush:**
1. **Need generated ID immediately**
```java
Article article = new Article();
articleRepository.saveAndFlush(article);
Long id = article.getId();  // Guaranteed to be set
```

2. **Trigger database constraints**
```java
User user = new User();
user.setEmail("duplicate@example.com");
userRepository.saveAndFlush(user);  // Exception if email exists
```

3. **Mixed operations**
```java
articleRepository.saveAndFlush(article);
// Database updated, can execute native queries
```

**Performance:**
- `save()` is faster (batching)
- Use `saveAndFlush()` only when necessary

---

### Q46: How do you handle circular dependencies in Spring?

**Answer:**
Circular dependency occurs when Bean A depends on Bean B, and Bean B depends on Bean A.

**Problem:**
```java
@Service
public class ServiceA {
    private final ServiceB serviceB;
    
    public ServiceA(ServiceB serviceB) {
        this.serviceB = serviceB;
    }
}

@Service
public class ServiceB {
    private final ServiceA serviceA;
    
    public ServiceB(ServiceA serviceA) {
        this.serviceA = serviceA;
    }
}
// Error: The dependencies of some beans form a cycle
```

**Solutions:**

**1. Redesign (Best)**
```java
// Extract common logic to ServiceC
@Service
public class ServiceC {
    public void commonLogic() { }
}

@Service
public class ServiceA {
    private final ServiceC serviceC;
}

@Service
public class ServiceB {
    private final ServiceC serviceC;
}
```

**2. @Lazy**
```java
@Service
public class ServiceA {
    private final ServiceB serviceB;
    
    public ServiceA(@Lazy ServiceB serviceB) {
        this.serviceB = serviceB;
    }
}
```
- Injects proxy
- Actual bean created when first used

**3. Setter Injection**
```java
@Service
public class ServiceA {
    private ServiceB serviceB;
    
    @Autowired
    public void setServiceB(ServiceB serviceB) {
        this.serviceB = serviceB;
    }
}
```

**4. @PostConstruct**
```java
@Service
public class ServiceA {
    @Autowired
    private ApplicationContext context;
    
    private ServiceB serviceB;
    
    @PostConstruct
    public void init() {
        serviceB = context.getBean(ServiceB.class);
    }
}
```

---

### Q47: What are actuator endpoints and how to secure them?

**Answer:**
Spring Boot Actuator provides production-ready features.

**Project Configuration:**
```properties
management.endpoints.web.exposure.include=health
management.endpoint.health.show-details=always
```

**Common Endpoints:**
- `/actuator/health` - Health status
- `/actuator/info` - Application info
- `/actuator/metrics` - Application metrics
- `/actuator/env` - Environment properties
- `/actuator/loggers` - Logging configuration

**Security Configuration:**
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) {
    return http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/actuator/health").permitAll()
            .requestMatchers("/actuator/**").hasRole("ADMIN")
            .anyRequest().authenticated()
        )
        .build();
}
```

**Custom Health Indicator:**
```java
@Component
public class DatabaseHealthIndicator implements HealthIndicator {
    
    @Autowired
    private DataSource dataSource;
    
    @Override
    public Health health() {
        try (Connection conn = dataSource.getConnection()) {
            return Health.up()
                .withDetail("database", "PostgreSQL")
                .withDetail("status", "Connected")
                .build();
        } catch (SQLException e) {
            return Health.down()
                .withDetail("error", e.getMessage())
                .build();
        }
    }
}
```

---

### Q48: Explain Spring Profiles and their use cases.

**Answer:**
Profiles provide environment-specific configurations.

**Configuration:**
```properties
# application.properties (default)
spring.profiles.active=dev

# application-dev.properties
spring.datasource.url=jdbc:postgresql://localhost:5432/articledb_dev
logging.level.org.aryan=DEBUG

# application-prod.properties
spring.datasource.url=jdbc:postgresql://prod-server:5432/articledb
logging.level.org.aryan=INFO
```

**Conditional Beans:**
```java
@Configuration
@Profile("dev")
public class DevConfig {
    
    @Bean
    public DataSource devDataSource() {
        // H2 in-memory database for development
        return new EmbeddedDatabaseBuilder()
            .setType(EmbeddedDatabaseType.H2)
            .build();
    }
}

@Configuration
@Profile("prod")
public class ProdConfig {
    
    @Bean
    public DataSource prodDataSource() {
        // PostgreSQL for production
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(jdbcUrl);
        return new HikariDataSource(config);
    }
}
```

**Activate Profiles:**

**1. application.properties:**
```properties
spring.profiles.active=dev,debug
```

**2. Command line:**
```bash
java -jar app.jar --spring.profiles.active=prod
```

**3. Environment variable:**
```bash
export SPRING_PROFILES_ACTIVE=prod
java -jar app.jar
```

**4. Docker:**
```yaml
services:
  app:
    environment:
      SPRING_PROFILES_ACTIVE: prod
```

**Use Cases:**
- Development vs Production configs
- Feature flags
- Region-specific settings
- Testing configurations

---

### Q49: How would you implement API versioning?

**Answer:**
API versioning maintains backward compatibility while evolving API.

**Strategies:**

**1. URI Versioning (Recommended)**
```java
@RestController
@RequestMapping("/api/v1/articles")
public class ArticleControllerV1 {
    @GetMapping
    public List<ArticleResponseV1> getArticles() {
        // Version 1 implementation
    }
}

@RestController
@RequestMapping("/api/v2/articles")
public class ArticleControllerV2 {
    @GetMapping
    public List<ArticleResponseV2> getArticles() {
        // Version 2 with additional fields
    }
}
```
**Pros:** Clear, easy to route, cacheable
**Cons:** URL pollution

**2. Header Versioning**
```java
@RestController
@RequestMapping("/api/articles")
public class ArticleController {
    
    @GetMapping(headers = "X-API-VERSION=1")
    public List<ArticleResponseV1> getArticlesV1() { }
    
    @GetMapping(headers = "X-API-VERSION=2")
    public List<ArticleResponseV2> getArticlesV2() { }
}
```
**Pros:** Clean URLs
**Cons:** Not visible, hard to test in browser

**3. Accept Header (Content Negotiation)**
```java
@GetMapping(produces = "application/vnd.article.v1+json")
public ArticleResponseV1 getArticleV1() { }

@GetMapping(produces = "application/vnd.article.v2+json")
public ArticleResponseV2 getArticleV2() { }
```
**Pros:** RESTful
**Cons:** Complex

**4. Query Parameter**
```java
@GetMapping
public ResponseEntity<?> getArticles(
    @RequestParam(defaultValue = "1") int version) {
    if (version == 1) return getV1();
    if (version == 2) return getV2();
}
```
**Pros:** Simple
**Cons:** Not RESTful

---

### Q50: What security best practices are implemented in the project?

**Answer:**

**1. Password Security**
- BCrypt hashing with salt
- Strong password policy (regex validation)
- No plaintext storage

**2. Token Security**
- Short-lived access tokens (15 min)
- Refresh token rotation
- Token stored server-side for revocation
- Signature verification (HS256)

**3. Account Protection**
- Email verification required
- Account lockout (5 failed attempts)
- 24-hour automatic unlock
- Rate limiting on auth endpoints

**4. API Security**
- JWT authentication
- Stateless sessions
- CORS configuration
- HTTPS recommended (production)

**5. Input Validation**
- Bean Validation on DTOs
- SQL injection prevention (JPA)
- XSS prevention (input sanitization)

**6. Information Disclosure**
- Generic error messages
- No stack traces in production
- Masked sensitive data in logs

**7. Rate Limiting**
- Per-IP limits
- Stricter limits on auth endpoints
- DoS attack prevention

**8. Database Security**
- Parameterized queries
- Least privilege principle
- Connection pool limits

**9. Dependency Security**
- Regular dependency updates
- No known vulnerabilities
- Maven dependency check

**10. Monitoring**
- Actuator health checks
- Logging (failed login, exceptions)
- Audit trail for sensitive operations

---

## 📝 Additional Interview Tips

### General Advice:

**1. Understand, Don't Memorize**
- Explain concepts in your own words
- Use examples from this project
- Discuss trade-offs

**2. Discuss Trade-offs**
- Every design decision has pros/cons
- Example: "I used BCrypt instead of plain hashing because..."

**3. Real-World Context**
- "In my Article Management project, I implemented..."
- Show practical application

**4. Ask Clarifying Questions**
- "Are you asking about development or production setup?"
- Shows thoughtful approach

**5. Be Honest**
- "I haven't used that specific technology, but I've used similar..."
- Willingness to learn matters

---

## 🎯 Topics to Deep Dive

Based on the project, focus on:

1. **Spring Boot Core** - DI, Auto-configuration
2. **Spring Security** - JWT, Authentication flow
3. **Spring Data JPA** - Relationships, Queries, N+1
4. **REST API Design** - HTTP methods, Status codes
5. in Spring:**
1. **Constructor Injection** (Recommended)
2. **Setter Injection**
3. **Field Injection**

**Example from project:**
```java
@Service
@RequiredArgsConstructor  // Lombok generates constructor
public class ArticleService {
    private final ArticleRepository articleRepository;
    private final UserRepository userRepository;
    
    // Dependencies injected via constructor
}
```

**Benefits:**
- Loose coupling
- Easy testing (mock dependencies)
- Single Responsibility Principle
- Immutability (with constructor injection)

---

### Q3: What are Spring Boot Starters?

**Answer:**
Starters are pre-configured dependency descriptors that include all necessary dependencies for a particular functionality.

**Examples from project:**
```xml
<!-- Web applications -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>

<!-- Security -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<!-- JPA -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
```

---

### Q4: What is @SpringBootApplication annotation?

**Answer:**
It's a convenience annotation that combines three annotations:

```java
@SpringBootApplication = 
    @Configuration +           // Allows bean definitions
    @EnableAutoConfiguration + // Enables auto-configuration
    @ComponentScan            // Scans for components
```

**What it does:**
- Marks the main configuration class
- Enables component scanning in current package and sub-packages
- Triggers auto-configuration based on classpath

---

### Q5: How does Spring Boot auto-configuration work?

**Answer:**
Auto-configuration attempts to automatically configure Spring application based on jar dependencies added.

**Mechanism:**
1. Loads configurations from `META-INF/spring.factories`
2. Evaluates `@Conditional` annotations
3. Configures beans if conditions are met

**Example:**
```java
@Configuration
@ConditionalOnClass(DataSource.class)
@ConditionalOnMissingBean
public class DataSourceAutoConfiguration {
    @Bean
    public DataSource dataSource() {
        // Configure DataSource
    }
}
```

**Project example:** HikariCP is auto-configured when `spring-boot-starter-data-jpa` is present.

---

## 2. Spring Security & JWT

### Q6: How does JWT authentication work?

**Answer:**
JWT (JSON Web Token) is a stateless authentication mechanism.

**Flow:**
1. **Login:** User sends credentials
2. **Token Generation:** Server validates and creates JWT
3. **Token Storage:** Client stores token (localStorage/cookie)
4. **Authenticated Requests:** Client sends token in Authorization header
5. **Token Validation:** Server validates token on each request

**JWT Structure:**
```
Header.Payload.Signature

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNjk5OTk5OTk5fQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Components:**
- **Header:** Algorithm and token type
- **Payload:** Claims (user data)
- **Signature:** Verify integrity

**Project Implementation:**
```java
@Service
public class JwtService {
    public String generateAccessToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
}
```

---

### Q7: What's the difference between Access Token and Refresh Token?

**Answer:**

| Aspect | Access Token | Refresh Token |
|--------|-------------|---------------|
| **Lifetime** | Short (15 minutes) | Long (7 days) |
| **Purpose** | Access protected resources | Get new access token |
| **Storage** | Memory/sessionStorage | Secure httpOnly cookie |
| **Exposure** | Sent with every request | Rarely used |
| **Revocation** | Not stored in DB | Stored in DB |

**Why use both?**
- **Security:** Short-lived access tokens limit exposure
- **User Experience:** Refresh tokens prevent frequent re-login
- **Revocation:** Can invalidate refresh tokens server-side

**Project Implementation:**
```java
// Access token - 15 minutes
jwt.access-token-expiration=900000

// Refresh token - 7 days  
jwt.refresh-token-expiration=604800000
```

---

### Q8: Explain the SecurityFilterChain in your project.

**Answer:**
SecurityFilterChain configures Spring Security's filter chain.

**Project Configuration:**
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) {
    return http
        .csrf(AbstractHttpConfigurer::disable)  // Disable CSRF for stateless API
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/auth/**").permitAll()  // Public endpoints
            .anyRequest().authenticated()                 // All others need auth
        )
        .sessionManagement(session -> 
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
        .build();
}
```

**Key Points:**
- **CSRF disabled:** Not needed for stateless APIs
- **Stateless sessions:** No session stored on server
- **Custom filter:** JWT validation before Spring Security's auth filter

---

### Q9: How does JwtAuthenticationFilter work?

**Answer:**
It intercepts every request to validate JWT tokens.

**Flow:**
```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) {
        // 1. Extract token from Authorization header
        String jwt = extractTokenFromHeader(request);
        
        // 2. Extract username from token
        String userEmail = jwtService.extractUsername(jwt);
        
        // 3. Load user details
        UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
        
        // 4. Validate token
        if (jwtService.validateToken(jwt, userDetails)) {
            // 5. Create authentication object
            UsernamePasswordAuthenticationToken authToken = 
                new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities()
                );
            
            // 6. Set authentication in SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }
        
        // 7. Continue filter chain
        filterChain.doFilter(request, response);
    }
}
```

**Why OncePerRequestFilter?**
- Guarantees single execution per request
- Handles async requests correctly

---

### Q10: What is BCrypt and why use it?

**Answer:**
BCrypt is a password hashing function designed for security.

**Features:**
- **Salting:** Prevents rainbow table attacks
- **Adaptive:** Can increase rounds as hardware improves
- **Slow by design:** Makes brute-force attacks difficult

**How it works:**
```
Password: "MyPassword123"
Salt: Random generated
Hash: $2a$10$N9qo8uLOickgx2ZMRZoMye/IVI47q.gJKN8EcGHL0.fHWMjBXN7my
```

**Project Usage:**
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}

// Registration
String hashedPassword = passwordEncoder.encode(rawPassword);

// Login
boolean matches = passwordEncoder.matches(rawPassword, hashedPassword);
```

---

## 3. Spring Data JPA

### Q11: What is JPA and how is it different from Hibernate?

**Answer:**

| Aspect | JPA | Hibernate |
|--------|-----|-----------|
| **Nature** | Specification | Implementation |
| **Role** | Defines interfaces | Provides concrete classes |
| **Annotations** | `@Entity`, `@Id`, etc. | All JPA + additional |
| **Vendor** | Java EE standard | ORM framework |

**Relationship:**
```
JPA (Specification)
  ↓
Hibernate (Implementation)
  ↓
Your Application
```

**Project Example:**
```java
@Entity  // JPA annotation
@Table(name = "users")  // JPA annotation
public class User {
    @Id  // JPA annotation
    @GeneratedValue(strategy = GenerationType.IDENTITY)  // JPA annotation
    private Long id;
}
```

---

### Q12: Explain the @Entity lifecycle callbacks in your project.

**Answer:**
JPA provides callback annotations for entity lifecycle events.

**Project Implementation:**
```java
@Entity
public class Article {
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    
    @PrePersist  // Before INSERT
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        if (status == null) status = ArticleStatus.PUBLISHED;
        if (viewCount == null) viewCount = 0L;
    }
    
    @PreUpdate  // Before UPDATE
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
```

**All Callbacks:**
- `@PrePersist` - Before entity persisted
- `@PostPersist` - After entity persisted
- `@PreUpdate` - Before entity updated
- `@PostUpdate` - After entity updated
- `@PreRemove` - Before entity removed
- `@PostRemove` - After entity removed
- `@PostLoad` - After entity loaded

---

### Q13: What is the difference between @OneToMany and @ManyToOne?

**Answer:**

**@OneToMany** - One entity has many related entities
```java
@Entity
public class User {
    @OneToMany(mappedBy = "author", cascade = CascadeType.ALL)
    private List<Article> articles;
}
```

**@ManyToOne** - Many entities reference one entity
```java
@Entity
public class Article {
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "author_id")
    private User author;
}
```

**Key Points:**
- `mappedBy` indicates the inverse side
- `@JoinColumn` specifies foreign key column
- Bidirectional relationships need both sides

**Fetching Strategies:**
- `LAZY` (Default for @OneToMany): Load when accessed
- `EAGER` (Default for @ManyToOne): Load immediately

---

### Q14: What is N+1 query problem? How to solve it?

**Answer:**
N+1 problem occurs when fetching a collection triggers one query for parent + N queries for children.

**Example Problem:**
```java
// 1 query to fetch all articles
List<Article> articles = articleRepository.findAll();

// N queries to fetch each author (if LAZY loading)
for (Article article : articles) {
    System.out.println(article.getAuthor().getName());  // Extra query!
}
```

**Solutions:**

**1. JOIN FETCH (JPQL)**
```java
@Query("SELECT a FROM Article a JOIN FETCH a.author")
List<Article> findAllWithAuthors();
```

**2. EntityGraph**
```java
@EntityGraph(attributePaths = {"author"})
List<Article> findAll();
```

**3. Batch Size**
```java
@BatchSize(size = 10)
@ManyToOne
private User author;
```

**Project Note:** We use `FetchType.LAZY` and selective fetching.

---

### Q15: Explain transaction management with @Transactional.

**Answer:**
`@Transactional` ensures database operations are atomic.

**Project Usage:**
```java
@Service
public class AuthService {
    
    @Transactional  // All operations in one transaction
    public MessageResponse register(RegisterRequest request) {
        // 1. Save user
        userRepository.save(user);
        
        // 2. Send email (if fails, rollback user creation)
        emailService.sendVerificationEmail(...);
        
        return new MessageResponse("Success");
    }
}
```

**Attributes:**
```java
@Transactional(
    propagation = Propagation.REQUIRED,  // Join existing or create new
    isolation = Isolation.DEFAULT,        // Database default
    readOnly = false,                     // Read-write transaction
    rollbackFor = Exception.class,        // Rollback on any exception
    timeout = 30                          // 30 seconds timeout
)
```

**When is transaction committed?**
- When method completes successfully
- When no RuntimeException is thrown

**When is transaction rolled back?**
- RuntimeException or Error thrown
- Explicitly marked with `rollbackFor`

---

## 4. RESTful API Design

### Q16: What are REST principles?

**Answer:**
REST (Representational State Transfer) architectural principles:

**1. Client-Server Separation**
- Client and server are independent
- Can evolve separately

**2. Stateless**
- Each request contains all necessary information
- No session stored on server

**3. Cacheable**
- Responses explicitly indicate if cacheable
- Improves performance

**4. Uniform Interface**
- Consistent resource identification (URIs)
- Standard HTTP methods

**5. Layered System**
- Client doesn't know if connected directly to server
- Allows load balancers, caches, etc.

**Project Implementation:**
```java
// Resource-based URLs
GET    /api/articles           // Get all articles
GET    /api/articles/1         // Get specific article
POST   /api/articles           // Create article
PUT    /api/articles/1         // Update article
DELETE /api/articles/1         // Delete article
```

---

### Q17: Explain HTTP status codes used in the project.

**Answer:**

**Success (2xx):**
- **200 OK:** Request succeeded (GET, PUT, DELETE)
- **201 Created:** Resource created (POST)
- **204 No Content:** Success but no body returned

**Client Errors (4xx):**
- **400 Bad Request:** Invalid input
- **401 Unauthorized:** Authentication required
- **403 Forbidden:** Authenticated but not authorized
- **404 Not Found:** Resource doesn't exist
- **409 Conflict:** Email already exists
- **423 Locked:** Account locked
- **429 Too Many Requests:** Rate limit exceeded

**Server Errors (5xx):**
- **500 Internal Server Error:** Unexpected error
- **503 Service Unavailable:** Server overloaded

**Project Examples:**
```java
// 201 Created
return ResponseEntity.status(HttpStatus.CREATED).body(article);

// 200 OK
return ResponseEntity.ok(articles);

// 404 Not Found
throw new ResourceNotFoundException("Article not found");
```

---

### Q18: What is pagination and why is it important?

**Answer:**
Pagination divides large datasets into smaller pages.

**Benefits:**
- **Performance:** Don't load all records at once
- **Memory:** Reduces memory consumption
- **User Experience:** Faster response times
- **Network:** Less data transferred

**Project Implementation:**
```java
@GetMapping("/articles")
public ResponseEntity<Page<ArticleResponse>> getAllArticles(
    @RequestParam(defaultValue = "0") int page,
    @RequestParam(defaultValue = "10") int size,
    @RequestParam(defaultValue = "createdAt") String sortBy,
    @RequestParam(defaultValue = "desc") String sortDir) {
    
    Sort sort = sortDir.equalsIgnoreCase("asc") ?
        Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        
    Pageable pageable = PageRequest.of(page, size, sort);
    
    Page<ArticleResponse> articles = articleService.getAllArticles(pageable);
    return ResponseEntity.ok(articles);
}
```

**Response Structure:**
```json
{
  "content": [...],
  "pageable": {
    "pageNumber": 0,
    "pageSize": 10,
    "sort": {"sorted": true}
  },
  "totalElements": 100,
  "totalPages": 10,
  "last": false,
  "first": true
}
```

---

### Q19: How do you handle CORS in Spring Boot?

**Answer:**
CORS (Cross-Origin Resource Sharing) allows or restricts resources to be requested from another domain.

**Project Configuration:**
```java
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins("http://localhost:3000", "https://yourdomain.com")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(3600);  // Cache preflight for 1 hour
    }
}
```

**Alternative - Controller Level:**
```java
@CrossOrigin(origins = "http://localhost:3000")
@RestController
public class ArticleController {
    // ...
}
```

**When is CORS needed?**
- Frontend (localhost:3000) calling Backend (localhost:8080)
- Different domains/ports/protocols

---

### Q20: What is the difference between @RequestBody and @RequestParam?

**Answer:**

**@RequestBody** - Extracts entire request body
```java
@PostMapping("/articles")
public Article create(@RequestBody ArticleRequest request) {
    // request = {title: "...", content: "..."}
}

// Request:
// POST /api/articles
// Body: {"title": "Spring Boot", "content": "..."}
```

**@RequestParam** - Extracts query parameters
```java
@GetMapping("/articles")
public List<Article> search(@RequestParam String keyword) {
    // keyword = "spring"
}

// Request:
// GET /api/articles?keyword=spring
```

**@PathVariable** - Extracts from URL path
```java
@GetMapping("/articles/{id}")
public Article getById(@PathVariable Long id) {
    // id = 1
}

// Request:
// GET /api/articles/1
```

---

## 5. Exception Handling

### Q21: Explain @RestControllerAdvice in your project.

**Answer:**
`@RestControllerAdvice` handles exceptions globally across all controllers.

**Project Implementation:**
```java
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFound(
            ResourceNotFoundException ex, WebRequest request) {
        
        log.error("Resource not found: {}", ex.getMessage());
        
        ErrorResponse error = new ErrorResponse(
                HttpStatus.NOT_FOUND.value(),
                ex.getMessage(),
                LocalDateTime.now(),
                request.getDescription(false)
        );
        
        return new ResponseEntity<>(error, HttpStatus.NOT_FOUND);
    }
    
    // More handlers...
}
```

**Benefits:**
- **Centralized:** Single place for error handling
- **Consistent:** Uniform error responses
- **Clean:** Controllers focus on business logic
- **Maintainable:** Easy to modify error handling

---

### Q22: What are custom exceptions and why use them?

**Answer:**
Custom exceptions provide domain-specific error handling.

**Project Examples:**
```java
// Custom exception
public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String message) {
        super(message);
    }
}

// Usage in service
public Article getById(Long id) {
    return articleRepository.findById(id)
        .orElseThrow(() -> 
            new ResourceNotFoundException("Article not found with id: " + id)
        );
}
```

**Benefits:**
- **Semantic:** Clear what error occurred
- **Type-safe:** Compiler checks exception types
- **Specific handling:** Different exceptions → different responses
- **Business logic:** Express domain errors explicitly

**Project Custom Exceptions:**
- `ResourceNotFoundException` → 404
- `EmailAlreadyExistsException` → 409
- `UnauthorizedException` → 401
- `ForbiddenException` → 403
- `RateLimitExceededException` → 429
- `TokenExpiredException` → 401

---

### Q23: How do you handle validation errors?

**Answer:**
Bean Validation (Jakarta Validation) with custom error handling.

**1. Add Validation Annotations:**
```java
public class RegisterRequest {
    @NotBlank(message = "Name is required")
    @Size(min = 2, max = 100)
    private String name;
    
    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    private String email;
    
    @NotBlank
    @Size(min = 8)
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$",
             message = "Password must contain digit, lowercase, uppercase, special char")
    private String password;
}
```

**2. Use @Valid in Controller:**
```java
@PostMapping("/register")
public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
    // Validation happens before method execution
}
```

**3. Handle MethodArgumentNotValidException:**
```java
@ExceptionHandler(MethodArgumentNotValidException.class)
public ResponseEntity<ValidationErrorResponse> handleValidationErrors(
        MethodArgumentNotValidException ex) {
    
    Map<String, String> errors = new HashMap<>();
    ex.getBindingResult().getAllErrors().forEach(error -> {
        String fieldName = ((FieldError) error).getField();
        String errorMessage = error.getDefaultMessage();
        errors.put(fieldName, errorMessage);
    });
    
    ValidationErrorResponse response = new ValidationErrorResponse(
        400,
        "Validation failed",
        errors,
        LocalDateTime.now()
    );
    
    return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
}
```

**Response Example:**
```json
{
  "status": 400,
  "message": "Validation failed",
  "errors": {
    "email": "Email must be valid",
    "password": "Password must contain digit, lowercase, uppercase, special char"
  },
  "timestamp": "2024-11-04T10:30:00"
}
```

---

## 6. Email Integration

### Q24: How does async email sending work in your project?

**Answer:**
Asynchronous email sending prevents blocking the main thread.

**Configuration:**
```java
@Configuration
@EnableAsync
public class AsyncConfig {
    
    @Bean(name = "taskExecutor")
    public Executor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);          // Minimum threads
        executor.setMaxPoolSize(5);           // Maximum threads
        executor.setQueueCapacity(100);       // Queue size
        executor.setThreadNamePrefix("async-email-");
        executor.initialize();
        return executor;
    }
}
```

**Service Implementation:**
```java
@Service
public class EmailService {
    
    @Async("taskExecutor")  // Run in separate thread
    @Retryable(  // Retry on failure
        retryFor = {MailException.class},
        maxAttempts = 3,
        backoff = @Backoff(delay = 2000, multiplier = 2)
    )
    public void sendVerificationEmail(String to, String name, String token) {
        // Send email
        log.info("Sending email in thread: {}", 
                 Thread.currentThread().getName());
    }
}
```

**Benefits:**
- **Non-blocking:** Main thread continues immediately
- **Better UX:** Faster API responses
- **Resilience:** Retry failed emails
- **Scalability:** Handle multiple emails concurrently

---

### Q25: Explain retry mechanism for email sending.

**Answer:**
Retry mechanism attempts failed operations multiple times.

**Project Configuration:**
```java
@Configuration
@EnableRetry
public class RetryConfig {
}

@Service
public class EmailService {
    
    @Retryable(
        retryFor = {MailException.class, MessagingException.class},
        maxAttempts = 3,
        backoff = @Backoff(delay = 2000, multiplier = 2)
    )
    public void sendEmail(String to, String subject, String content) {
        // Attempt 1: delay = 0ms
        // Attempt 2: delay = 2000ms (if fails)
        // Attempt 3: delay = 4000ms (if fails)
        mailSender.send(message);
    }
}
```

**Backoff Strategy:**
- **Fixed Delay:** Same delay between attempts
- **Exponential Backoff:** Increasing delay (2s, 4s, 8s)

**When to use:**
- Network timeouts
- Temporary service unavailability
- Rate limiting from external services

**Alternative - @Recover:**
```java
@Recover
public void recoverFromEmailFailure(MailException e, String to) {
    log.error("Failed to send email to {} after retries", to);
    // Save to database for manual retry
}
```

---

### Q26: Why use Thymeleaf for email templates?

**Answer:**
Thymeleaf is a server-side template engine for HTML.

**Benefits:**
- **Type-safe:** Compile-time checking
- **Natural templates:** Valid HTML that renders in browser
- **Integration:** Works seamlessly with Spring
- **Internationalization:** Built-in i18n support

**Project Template Example:**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
    <h2>Welcome to Article Management!</h2>
    <p>Hi <span th:text="${name}">User</span>,</p>
    <p>Click below to verify your email:</p>
    <a th:href="${verificationLink}" class="button">
        Verify Email
    </a>
</body>
</html>
```

**Processing:**
```java
Context context = new Context();
context.setVariables(Map.of(
    "name", "John Doe",
    "verificationLink", "https://app.com/verify?token=abc123"
));

String htmlContent = templateEngine.process("email-verification", context);
```

---

## 7. Caching & Performance

### Q27: How does Spring caching work in your project?

**Answer:**
Spring Cache abstraction provides caching without changing business logic.

**Configuration:**
```java
@Configuration
@EnableCaching
public class CacheConfig {
}

// application.properties
spring.cache.cache-names=rate-limit-buckets
spring.cache.caffeine.spec=maximumSize=100000,expireAfterWrite=3600s
```

**Usage:**
```java
@Service
public class RateLimitService {
    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();
    
    public Bucket resolveBucket(String key) {
        return cache.computeIfAbsent(key, k -> createBucket(100, 1));
    }
}
```

**Cache Providers:**
- **Caffeine:** In-memory, high-performance (used in project)
- **Redis:** Distributed, production-grade
- **EhCache:** Java-based, configurable

**Benefits:**
- **Performance:** Avoid repeated computations
- **Reduced load:** Less database queries
- **Scalability:** Handle more requests

---

### Q28: What is HikariCP and why use it?

**Answer:**
HikariCP is a high-performance JDBC connection pool.

**Why Connection Pooling?**
Creating database connections is expensive:
- TCP connection establishment
- Authentication
- Resource allocation

**How it works:**
```
Application → Connection Pool → Database
              ↑ Reuse connections
```

**Project Configuration:**
```properties
spring.datasource.hikari.maximum-pool-size=10
spring.datasource.hikari.minimum-idle=5
spring.datasource.hikari.connection-timeout=30000
spring.datasource.hikari.idle-timeout=600000
spring.datasource.hikari.max-lifetime=1800000
```

**Benefits:**
- **Performance:** Reuse connections
- **Resource management:** Limit concurrent connections
- **Monitoring:** Connection health checks
- **Default in Spring Boot:** Zero configuration needed

---

### Q29: Explain database indexing in your project.

**Answer:**
Indexes speed up database queries.

**Project Indexes:**
```java
@Entity
@Table(name = "users", indexes = {
    @Index(name = "idx_email", columnList = "email"),
    @Index(name = "idx_verification_token", columnList = "verification_token")
})
public class User {
    // ...
}

@Entity
@Table(name = "articles", indexes = {
    @Index(name = "idx_author_id", columnList = "author_id"),
    @Index(name = "idx_created_at", columnList = "created_at")
})
public class Article {
    // ...
}
```

**When to create indexes:**
- **Foreign keys:** Fast joins
- **Search fields:** Email, username
- **Sort fields:** created_at
- **Where clauses:** Frequently filtered columns

**Trade-offs:**
- ✅ Faster reads
- ❌ Slower writes (index must be updated)
- ❌ More storage space

**Types
