package ua.com.rocketlv.demoapp;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import ua.com.rocketlv.demoapp.filter.CustomAuthenticationFilter;
import ua.com.rocketlv.demoapp.filter.CustomAuthorizationFilter;


@Configuration
@EnableWebSecurity
//@RequiredArgsConstructor
public class SecurityConfiguration {

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter filter = new CustomAuthenticationFilter(
                authenticationManager(http.getSharedObject(AuthenticationConfiguration.class)));
                filter.setFilterProcessesUrl("/api/login");
        return http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests((requests) -> requests
                        .antMatchers("/","/api/login**","/api/refresh/token**", "/h2-console/**").permitAll()
                        .antMatchers(HttpMethod.GET, "/api/users/**").hasAnyRole ("ADMIN")
                        .antMatchers(HttpMethod.POST, "/api/user/**").hasAnyAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated()
                ).addFilterBefore(filter
                        , UsernamePasswordAuthenticationFilter.class
                )
                .addFilterBefore(
                        new CustomAuthorizationFilter()
                        , CustomAuthenticationFilter.class
                )
                .build();
    }


}
