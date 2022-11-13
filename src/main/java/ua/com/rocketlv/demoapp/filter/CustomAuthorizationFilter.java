package ua.com.rocketlv.demoapp.filter;


import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    private final JwtDecoder decoder;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("{}", request.getServletPath());
        if ((request.getServletPath().equals("/api/login")) || (request.getServletPath().equals("/api/refresh/token"))) {
            log.info(request.getServletPath());
            filterChain.doFilter(request, response);
        } else {
            try {
                String header = request.getHeader(HttpHeaders.AUTHORIZATION);
                String token = header.substring("Bearer ".length());
                log.info("used token {}", token);
                Jwt decoded = decoder.decode(token);

                String username = decoded.getSubject();
                decoded.getClaims().keySet().forEach(calm->log.info((calm.intern())));
                List<String> roles = decoded.getClaimAsStringList("roles");
                Collection<SimpleGrantedAuthority> ath = new ArrayList<>();
                roles.forEach(role -> {
                    ath.add(new SimpleGrantedAuthority(role));
                });
                UsernamePasswordAuthenticationToken authtoken = UsernamePasswordAuthenticationToken.authenticated(username, null, ath);
                SecurityContextHolder.getContext().setAuthentication(authtoken);
                filterChain.doFilter(request, response);
            } catch (Exception e) {
                log.error("DemoApp rise Exception {}", e.getMessage());
                response.setHeader("error", e.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                Map<String, String> errorMp = new HashMap<>();
                errorMp.put("error", e.getMessage());
                ObjectMapper mapper = new ObjectMapper();
                mapper.writeValue(response.getOutputStream(), errorMp);
            }
        }
    }
}
