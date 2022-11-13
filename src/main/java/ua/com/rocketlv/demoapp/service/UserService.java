package ua.com.rocketlv.demoapp.service;

import ua.com.rocketlv.demoapp.domain.Role;
import ua.com.rocketlv.demoapp.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    User addRoleToUser(String username, String role);
    User getUser(String username);
    List<User> getUsers();


}
