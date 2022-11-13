package ua.com.rocketlv.demoapp.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ua.com.rocketlv.demoapp.domain.Role;
import ua.com.rocketlv.demoapp.domain.User;
import ua.com.rocketlv.demoapp.reposytory.RoleRepo;
import ua.com.rocketlv.demoapp.reposytory.UserRepo;

import java.util.List;


@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService {
    final UserRepo userRepo;
    final RoleRepo roleRepo;
    final PasswordEncoder passwordEncoder;

    @Override
    public User saveUser(User user) {
    log.info("saved new user {}", user.getUsername());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saved new role {}", role.getName());
        return roleRepo.save(role);
    }

    @Override
    public User addRoleToUser(String username, String role) {
        log.info("add user {} to role {}", username, role);
        User user = userRepo.findByUsername(username);
        Role role_data = roleRepo.findByName(role);
        user.getRoles().add(role_data);
        return userRepo.save(user);
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching user {} from database", username);
        return userRepo.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("Fetching all users from database");
        return userRepo.findAll();
    }
}
