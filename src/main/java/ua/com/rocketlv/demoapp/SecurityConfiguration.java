package ua.com.rocketlv.demoapp;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    private final RSAKeyProperties rsa;

    public SecurityConfiguration(RSAKeyProperties rsa) {
        this.rsa = rsa;
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }


//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
//        return authenticationConfiguration.getAuthenticationManager();
//    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        CustomAuthenticationFilter filter = new CustomAuthenticationFilter(
//                authenticationManager(http.getSharedObject(AuthenticationConfiguration.class)), jwtEncoder());
//        filter.setFilterProcessesUrl("/api/login");
        return http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/", "/api/login**", "/api/refresh/token**", "/h2-console/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/users/**").hasAnyAuthority("SCOPE_ROLE_ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/user/**").hasAnyAuthority("SCOPE_ROLE_ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
//                .addFilterBefore(filter
//                        , UsernamePasswordAuthenticationFilter.class
//                )
//                .addFilterBefore(
//                        new CustomAuthorizationFilter(jwtDecoder())
//                        , CustomAuthenticationFilter.class
//                )
                .build();
    }

//    private JwtAuthenticationConverter jwtAuthenticationConverter() {
//        // create a custom JWT converter to map the roles from the token as granted authorities
//        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
//        //jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName(JWT_ROLE_NAME); // default is: scope, scp
//        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_"); // default is: SCOPE_
//
//        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
//        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
//        return jwtAuthenticationConverter;
//    }

//    @Bean
//    JwtDecoder jwtDecoder() {
//        return NimbusJwtDecoder.withPublicKey(rsa.getPublicKey()).build();
//    }
//
//    @Bean
//    JwtEncoder jwtEncoder() {
//        JWK jwk = new RSAKey.Builder(rsa.getPublicKey()).privateKey(rsa.getPrivateKey()).build();
//        JWKSource<SecurityContext> source = new ImmutableJWKSet<>(new JWKSet(jwk));
//        return new NimbusJwtEncoder(source);
//    }

}
