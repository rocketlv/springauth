package ua.com.rocketlv.demoapp;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import ua.com.rocketlv.demoapp.domain.Role;
import ua.com.rocketlv.demoapp.domain.User;
import ua.com.rocketlv.demoapp.service.UserService;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication

public class DemoappApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoappApplication.class, args);
	}

	@Bean
	CommandLineRunner run(UserService userService, PasswordEncoder encoder) {
		return args -> {
			List<Role> lst=new ArrayList<>();
			lst.add(userService.saveRole(new Role(1L, "ROLE_ADMIN")));
			lst.add(userService.saveRole(new Role(2L, "ROLE_SPEC")));
			userService.saveUser(new User(1L, "rocketlv",
					"president", lst));
		};
	}
}
