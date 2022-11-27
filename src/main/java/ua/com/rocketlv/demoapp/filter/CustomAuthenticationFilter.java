package ua.com.rocketlv.demoapp.filter;


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import ua.com.rocketlv.demoapp.service.MyUserPrincipal;


import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtEncoder encoder;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username is {} and password is {}", username, password);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) throws IOException, ServletException {
        MyUserPrincipal user = (ua.com.rocketlv.demoapp.service.MyUserPrincipal) auth.getPrincipal();

        JwtClaimsSet access = JwtClaimsSet.builder()
                .issuer(request.getRequestURL().toString())
                .expiresAt((new Date(System.currentTimeMillis() + 1000 * 600)).toInstant())
                .subject(user.getUsername())
                .claim("scope", user.getAuthorities().stream().map(val -> val.getAuthority().toString()).collect(Collectors.joining(" ")))
                .build();
        JwtClaimsSet refresh = JwtClaimsSet.builder()
                .issuer(request.getRequestURL().toString())
                .expiresAt((new Date(System.currentTimeMillis() + 1000 * 600)).toInstant())
                .subject(user.getUsername())
                .claim("scope", user.getAuthorities().stream().map(val -> val.getAuthority().toString()).collect(Collectors.joining(" ")))
                .build();

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", encoder.encode(JwtEncoderParameters.from(access)).getTokenValue());
        tokens.put("refresh_token", encoder.encode(JwtEncoderParameters.from(refresh)).getTokenValue());
        response.setContentType(APPLICATION_JSON_VALUE);
        ObjectMapper om = new ObjectMapper();
        om.writeValue(response.getOutputStream(), tokens);
    }
}
