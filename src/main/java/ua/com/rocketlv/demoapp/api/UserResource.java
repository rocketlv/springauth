package ua.com.rocketlv.demoapp.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import ua.com.rocketlv.demoapp.domain.Role;
import ua.com.rocketlv.demoapp.domain.User;
import ua.com.rocketlv.demoapp.service.UserService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/api")
@Slf4j
public class UserResource {
    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsersList() {
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/addtouser")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.addRoleToUser(
                form.getUsername(), form.getRole()
        ));
    }

//    @PostMapping("/refresh/token")
//    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
//        try {
//            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
//            String token = header.substring("Bearer ".length());
//            log.info("used token {}", token);
//            Algorithm alg = Algorithm.HMAC256("secret".getBytes());
//            JWTVerifier verifier = JWT.require(alg).build();
//            DecodedJWT decoded = verifier.verify(token);
//            String username = decoded.getSubject();
//            decoded.getClaims().keySet().forEach(calm->log.info((calm.intern())));
//            User user = userService.getUser(username);
//
//            String access_token = JWT.create().withSubject(user.getUsername())
//                    .withExpiresAt(new Date(System.currentTimeMillis() + 1000 * 60))
//                    .withIssuer(request.getRequestURL().toString())
//                    .withClaim("roles", user.getRoles().stream().map(val->val.getName().toString()).collect(Collectors.toList()))
//                    .sign(alg);
//            String refresh_token = JWT.create().withSubject(user.getUsername())
//                    .withExpiresAt(new Date(System.currentTimeMillis() * 30 *60 *1000))
//                    .withIssuer(request.getRequestURL().toString())
//                    .sign(alg);
//            Map<String, String> tokens = new HashMap<>();
//            tokens.put("access_token", access_token);
//            tokens.put("refresh_token", refresh_token);
//            response.setContentType(APPLICATION_JSON_VALUE);
//            ObjectMapper om = new ObjectMapper();
//            om.writeValue(response.getOutputStream(),tokens);
//        } catch (Exception e) {
//            log.error("DemoApp rise Exception {}", e.getMessage());
//            response.setHeader("error", e.getMessage());
//            response.setContentType(APPLICATION_JSON_VALUE);
//            Map<String, String> errorMp = new HashMap<>();
//            errorMp.put("error", e.getMessage());
//            ObjectMapper mapper = new ObjectMapper();
//            mapper.writeValue(response.getOutputStream(), errorMp);
//        }
//    }


    @Data
    class RoleToUserForm {
        private String username;
        private String role;
    }

}
