package ua.com.rocketlv.demoapp.reposytory;

import org.springframework.data.jpa.repository.JpaRepository;
import ua.com.rocketlv.demoapp.domain.Role;
import ua.com.rocketlv.demoapp.domain.User;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
