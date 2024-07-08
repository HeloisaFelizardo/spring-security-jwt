# Spring Boot Security com JWT

- Habilitando segurança em nossa API
- Algumas formas de configurar segurança
- Configurar manualmente a segurança da nossa API
- Consultar os usuários em banco de dados
- Melhorar a segurança da API com JWT

Este é um projeto de demonstração para implementar autenticação e autorização com JWT (JSON Web Token) utilizando Spring Boot.

## Descrição

O projeto demonstra como configurar e utilizar o Spring Security juntamente com JWT para proteger endpoints RESTful. Inclui exemplos de configuração de segurança, criação e validação de tokens JWT e controle de acesso a diferentes recursos da aplicação.

## Tecnologias Utilizadas

- Spring Boot 2.5.5
- Spring Security
- Spring Data JPA
- H2 Database
- JWT (JSON Web Token)
- Maven

### Executando o Projeto

Para executar o projeto localmente, siga os seguintes passos:

1. Clone o repositório para sua máquina local.
   ```bash
   git clone https://github.com/seu-usuario/dio-spring-security-jwt.git
   ```
2. Navegue até o diretório do projeto.
   ```bash
   cd dio-spring-security-jwt
   ```
3. Execute o projeto utilizando Maven.
   ```bash
   mvn spring-boot:run
   ```

### Estrutura do Projeto

- **src/main/java**: Contém o código-fonte Java do projeto.
- **src/main/resources**: Contém os recursos estáticos e os arquivos de configuração.

### Endpoints

O projeto possui alguns endpoints de exemplo:

- **/login**: Endpoint para autenticação de usuários e geração de tokens JWT.
- **/users**: Endpoints para operações CRUD de usuários. O endpoint POST é público, mas o endpoint GET é protegido.
- **/managers**: Endpoint protegido acessível apenas para usuários com o papel "MANAGERS".

### Configuração de Segurança

A configuração de segurança está localizada na classe `WebSecurityConfig`, onde são definidos os filtros de autenticação e autorização, assim como as regras de acesso aos endpoints.

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    public BCryptPasswordEncoder encoder(){
        return new BCryptPasswordEncoder();
    }

    private static final String[] SWAGGER_WHITELIST = {
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/webjars/**"
    };

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers().frameOptions().disable();
        http.cors().and().csrf().disable()
                .addFilterAfter(new JWTFilter(), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers(SWAGGER_WHITELIST).permitAll()
                .antMatchers("/h2-console/**").permitAll()
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                .antMatchers(HttpMethod.POST, "/users").permitAll()
                .antMatchers(HttpMethod.GET, "/users").hasAnyRole("USERS", "MANAGERS")
                .antMatchers("/managers").hasAnyRole("MANAGERS")
                .anyRequest().authenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Bean
    public ServletRegistrationBean<WebServlet> h2servletRegistration(){
        ServletRegistrationBean<WebServlet> registrationBean = new ServletRegistrationBean<>(new WebServlet());
        registrationBean.addUrlMappings("/h2-console/*");
        return registrationBean;
    }
}
```

### Banco de Dados

O projeto utiliza o banco de dados H2 em memória para facilitar os testes e o desenvolvimento. A configuração do banco de dados está localizada no arquivo `application.properties`.

### Obs.:
Swagger está pronto para implementação, mas não foi implementado.

