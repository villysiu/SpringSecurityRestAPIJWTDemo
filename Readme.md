# Authentication with Spring Security and JSON Web Token (JWT)
![](https://raw.githubusercontent.com/villysiu/SpringSecurityRestAPIJWTDemo/refs/heads/main/src/main/resources/static/images/1_4kmMGfCuHJPtB4t0s5l30Q.webp)

[![Authentication by Spring Security adn JWT](https://markdown-videos-api.jorgenkh.no/url?url=https%3A%2F%2Fyoutube.com%2Fshorts%2F2e5bfzWMsWo)](https://youtube.com/shorts/2e5bfzWMsWo)

In this tutorial, we are building an authentication REST API Spring boot project with Spring Security and Jwt token.
This is based on my previous post Java Springboot signup/login Rest API. Instead of persisting the authenticated user into a HttpSession, we create a JSON Web Token with the authenticated user's email and persist it in a cookie in the response header. So everytime a request being sent, the cookie will be sent along, and jwt token will be extracted and validated, to see if user has authority to visit the link.
The configuration of my system
* Springboot 3.4.2
* Java 17
* JDK 23

## Create Spring boot application

Spring Boot provides a web tool called [Spring Initializer](https://start.spring.io/) to bootstrap an application quickly. Just go to [https://start.spring.io/](https://start.spring.io/) and generate a new spring boot project with Maven or use Intellij Idea.
Maven dependencies for the project:
* Spring Boot DevTools
* Spring Web
* Spring Security 6.0
* Lombak
* JDBC API
* Spring Data JPA
* MySQL

### Create MySQL database

Create a new database, springbootRestApiJWT, in MySQL server.

#### Setup connection to database

in /src/main/resources/application.properties, added the following text
```
spring.application.name=SpringSecurityRestAPI

spring.datasource.url = jdbc:mysql://localhost:3306/springbootRestApiJWT?useSSL=false&serverTimezone=UTC
spring.datasource.username = <-- insert your MySQL username -->
spring.datasource.password = <-- insert your MySQL password -->

# hibernate properties
spring.jpa.properties.hibernate.dialect = org.hibernate.dialect.MySQLDialect

# Hibernate ddl auto (create, create-drop, validate, update)
spring.jpa.hibernate.ddl-auto = update

logging.level.org.springframework.security=DEBUG

#jwt.token.secret

jwt.token.secret=${SECRET_KEY}
jwt.token.expires=30
```
The last 3 lines are for generating jwt token and decode. The token expiration time is saved as 30 minutes. These values will be injected to `@Value` for use.

#### Create a secret

Generate a secret key from [https://jwtsecret.com/generate](https://jwtsecret.com/generate).
On the bar on top, SpringSecurityRestApiApplication -> Edit Configuration
Look for `Edit Option`, enable `Environment Variable` by checking it.
In the `Environment Variable` input box, enter
```
SECRET_KEY=<-- the 128 bit secret key -->
```
Click `Apply`, then `Ok`.

![](https://camo.githubusercontent.com/3271b327d12ccb42674123ba0936b9c165cbb93d20ff26cc3bb2da99d50b101f/68747470733a2f2f6d69726f2e6d656469756d2e636f6d2f76322f726573697a653a6669743a343830302f666f726d61743a776562702f312a7a78644852702d4f61425469713358734446467047772e706e67)

#### pom.xml

Add the following dependencies in pom.xml in use jwt token, validation and logging. Press the M button to open the Maven panel and sync/refresh the maven project. Check out mavenrepository.com for latest version.
```
<!-- Validation -->
<dependency>
    <groupId>jakarta.validation</groupId>
    <artifactId>jakarta.validation-api</artifactId>
    <version>3.0.2</version>
</dependency>

<!-- json web token -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.12.6</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.6</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.12.6</version>
    <scope>runtime</scope>
</dependency>

<!-- Logging -->
<!-- https://mvnrepository.com/artifact/org.slf4j/slf4j-api -->
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-api</artifactId>
    <version>2.0.16</version>
</dependency>
```

#### Model/Entity

Create the model package in /src/main/java/com.villysiu.springsecurityrestapi . In the newly created model package, we will create the two entities, Account.java and Role.java, and an Enum class containing the Roles, ROLE_USER and ROLE_ADMIN.
```
@Entity
@Table
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor

public class Account {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @NotBlank(message = "Name is required")
    private String nickname;

    @NotBlank(message = "email is required")
    @Email
    @Column(unique = true)
    private String email;

    @NotBlank(message = "Password is required")
    private String password;

    @ManyToMany(fetch = FetchType.EAGER )
    @JoinTable(name = "account_roles",
            joinColumns = @JoinColumn(name = "account_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    public Account(String nickname, String email, String password) {
        this.nickname = nickname;
        this.email = email;
        this.password = password;
    }
}
```
```
@Entity
@Data
@NoArgsConstructor
public class Role {
@Id
@GeneratedValue(strategy = GenerationType.IDENTITY)
private Long id;

    @Enumerated(EnumType.STRING)
    private ERole erole = ERole.ROLE_USER;

    public Role(ERole erole) {
        this.erole = erole;
    }
}
```
```
public enum ERole {
    ROLE_USER,
    ROLE_ADMIN
}
```

#### Repository and JPA

Next we will create the repository package in `/src/main/java/com.villysiu.springsecurityrestapi` and create AccountRepository.java and RoleRepository.java that extends `JpaRepository` to interact with the database using the Java Persistence API (JPA). JPA provides built-in methods for basic CRUD operations, ie.`save()`, `findById()`, `findAll()`, and `delete()` and Pagination and Sorting, ie.`findAll(Pageable pageable)` and `findAll(Sort sort)`.
```
@Repository
public interface AccountRepository extends JpaRepository<Account, Long> {
Optional<Account> findByEmail(String email);
Boolean existsByEmail(String email);
}
```
```
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
Optional<Role> findByErole(ERole erole);
}
```

#### Service

we will create the service package in `/src/main/java/com.villysiu.springsecurityrestapi` and create a `CustomUserDetailsService.java` which implements the `UserDetailsService` interface.
```
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private  AccountRepository accountRepository;
    public CustomUserDetailsService(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Account account = accountRepository.findByEmail(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException(email + " not found." ));

        Set<GrantedAuthority> authorities = account
                .getRoles()
                .stream()
                .map((role) -> new SimpleGrantedAuthority(role.getErole().name()))
                .collect(Collectors.toSet());

        return new org.springframework.security.core.userdetails.User(
                account.getEmail(),
                account.getPassword(),
                authorities
        );
    }
}
```

#### JwtService

In service package, we create the JwtService.java, which contains the business login of jwt.

`void generateToken(String email, HttpServletResponse response)`generates a jwt token with `Jwts.builder()` and persists the token in a cookie, "JWT", in http response header. When user makes a request to the API, the cookie will be passed along in header and be verfied.
`void validateToken(String token) throws JwtExceptionvalidates` validates the token. If token is empty, expired, or not in valid format, JwtException will be thrown.
`String getJwtTokenFromCookie(HttpServletRequest request)`extracts the token from "JWT" cookie.
`void removeTokenFromCookie(HttpServletResponse response)`sets the "JWT" cookie to null.
`String extractEmail()`extracts the user's email

```
@Service
public class JwtService {

    // set in .env
    @Value("${jwt.token.secret}")
    private String secret;

    @Value("${jwt.token.expires}")
    private Long jwtExpiresMinutes;

    private Claims claims;

    public void generateToken(String email, HttpServletResponse response){
        String jwt = Jwts.builder()
                .subject(email) //username here is indeed the email
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpiresMinutes * 60 * 1000))
                .signWith(getSignInKey())
                .compact();

        Cookie cookie = new Cookie("JWT", jwt);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(24 * 60 * 60);
        response.addCookie(cookie);
    }

    public String getJwtFromCookie(HttpServletRequest request){
        Cookie cookie = WebUtils.getCookie(request, "JWT");
        if(cookie != null){
            return cookie.getValue();
        }
        return null;

    }
    public void validateToken(String token) throws JwtException {

        try {
            claims = Jwts.parser()
                    .verifyWith(getSignInKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

        } catch(JwtException e){
// catch null, wrong token, expired token
throw new JwtException(e.getMessage());
}
}
public void removeTokenFromCookie(HttpServletResponse response){
Cookie cookie = new Cookie("JWT", null);
cookie.setPath("/");

        response.addCookie(cookie);
    }

    private SecretKey getSignInKey() {
//        SignatureAlgorithm.HS256, this.secret
byte[] keyBytes = Decoders.BASE64.decode(this.secret);
return Keys.hmacShaKeyFor(keyBytes);
}

    public String extractEmail() {
        return claims.getSubject();
    }

}
```

#### AuthenticationService

In service package, we create the AuthenticationService.java, which contains the business logic of authentication through Spring Security, including login, signup and logout.
```
@Service
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final AccountRepository accountRepository;
    private final JwtService jwtService;
    private final RoleRepository roleRepository;

    public AuthenticationService(AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, AccountRepository accountRepository,  JwtService jwtService, RoleRepository roleRepository) {
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.accountRepository = accountRepository;
        this.jwtService = jwtService;
        this.roleRepository = roleRepository;
    }
    public String login(LoginRequest loginRequest, HttpServletResponse response) {

        Authentication authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.getEmail(), loginRequest.getPassword());
        Authentication authenticationResponse = this.authenticationManager.authenticate(authenticationRequest);

        SecurityContextHolder.getContext().setAuthentication(authenticationResponse);
        jwtService.generateToken(loginRequest.getEmail(), response);
        UserDetails userDetails = (UserDetails) authenticationResponse.getPrincipal();
        return userDetails.getUsername();
    }
    public void registerAccount(SignupRequest signupRequest){
        if(accountRepository.existsByEmail(signupRequest.getEmail())){
            throw new EntityExistsException("Email already used");
        }
        // create user object
        Account account = new Account(signupRequest.getName(), signupRequest.getEmail(), passwordEncoder.encode(signupRequest.getPassword()));
        Role role = roleRepository.findByErole(ERole.ROLE_USER).orElse(null);
        account.setRoles(Collections.singleton(role));
        accountRepository.save(account);

    }
    public void logoutUser(HttpServletResponse response){
        jwtService.removeTokenFromCookie(response);
    }
}
```

#### JwtAuthenticationFilter

In the config package, we will create the `JwtAuthenticationFilter.java`, which extends OncePerRequestFilter and override the `doFilterInternal() `method. `OncePerRequestFilter`, as its name said, is executed only once for a given request. When a `HttpServletRequest` comes in from an api client, we check the header for the cookie to extract Bearer token. If there is a valid Bearer token, we stored the user into the `SecurityContextHolder`, (which can be accessed by `@AuthenticationPrincipal UserDetails userDetails`) then we will continue in the chain of filter. To learn more about filter and chain of filter, check [Spring docs](https://medium.com/r/?url=https%3A%2F%2Fdocs.spring.io%2Fspring-security%2Freference%2Fservlet%2Farchitecture.html%23servlet-securityfilterchain) out.
```
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
private final JwtService jwtService;
private final CustomUserDetailsService customUserDetailsService;
public JwtAuthenticationFilter(JwtService jwtService, CustomUserDetailsService customUserDetailsService) {
this.jwtService = jwtService;
this.customUserDetailsService = customUserDetailsService;
}
private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        try {
            String jwt = jwtService.getJwtFromCookie(request);
            jwtService.validateToken(jwt);
            String userEmail = jwtService.extractEmail();

            UserDetails userDetails = customUserDetailsService.loadUserByUsername(userEmail);

            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authToken);
            SecurityContextHolder.setContext(context);

        } catch (Exception e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        }
        filterChain.doFilter(request, response);
    }
}
```
SecurityConfig
In SecurityConfig.java, we added the following line to run `JwtAuthenticationFilter` before the rest of the application.
```
.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
```
we changed Session to stateless because we no longer rely on server side for session management, as JWT wraps the informaton and stored in the cookie, which is sent in header along with any request.
```
.sessionManagement(manager -> manager
.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
```
Completed SecurityConfig.java Code
```
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exceptionHandling ->
                                exceptionHandling
                                .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                )
                .authorizeHttpRequests((auth) ->
                        auth.requestMatchers(HttpMethod.GET, "public_resource").permitAll()
                                .requestMatchers("/auth/**").permitAll()
                                .anyRequest().authenticated()
                )
                .sessionManagement(manager -> manager
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(authenticationProvider);
    }

    @Bean
    public static PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
```
#### Login Controller
```
@PostMapping("/signin")
public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response){
        try {
            String email = authenticationService.login(loginRequest, response);
            return new ResponseEntity<>(email+" signed in", HttpStatus.OK);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return new ResponseEntity<>(e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
}
```

#### Signup Controller
```
@PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest, HttpServletRequest request){
try {
authenticationService.registerAccount(signupRequest);
return new ResponseEntity<>("Account registered.", HttpStatus.CREATED);
} catch (Exception e) {
logger.error(e.getMessage());
return new ResponseEntity<>(e.getMessage(), HttpStatus.UNAUTHORIZED);
}
}
```

#### Logout Controller
```
@PostMapping("/signout")
public ResponseEntity<?> logoutUser(HttpServletResponse response) {
authenticationService.logoutUser(response);
return new ResponseEntity("You've been signed out!", HttpStatus.OK);
}
```

#### Resource Controller

Resource controller contains a public and private resource for testing.
```
@RestController
public class ResourceController {

    @GetMapping("/secret_resource")
    public ResponseEntity<String> secret(){
        return new ResponseEntity<>("You are viewing my secret" , HttpStatus.OK);
    }
    @GetMapping("/public_resource")
    public ResponseEntity<String> nosecret(){
        // assuming no existing user

        return new ResponseEntity<>("You are in public area", HttpStatus.OK);
    }
}
```
---
[![Authentication by Spring Security adn JWT](https://markdown-videos-api.jorgenkh.no/url?url=https%3A%2F%2Fyoutube.com%2Fshorts%2F2e5bfzWMsWo)](https://youtube.com/shorts/2e5bfzWMsWo)
We have finished all the coding, and now it is time to test out the Rest API with any Api client.**

