package ua.com.rocketlv.demoapp.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
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
                Algorithm alg = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier verifier = JWT.require(alg).build();
                DecodedJWT decoded = verifier.verify(token);
                String username = decoded.getSubject();
                decoded.getClaims().keySet().forEach(calm->log.info((calm.intern())));
                String[] roles = decoded.getClaim("roles").asArray(String.class);
                Collection<SimpleGrantedAuthority> ath = new ArrayList<>();
                Arrays.stream(roles).forEach(role -> {
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
