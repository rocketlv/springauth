package ua.com.rocketlv.demoapp.reposytory;

import org.springframework.data.jpa.repository.JpaRepository;
import ua.com.rocketlv.demoapp.domain.User;

public interface UserRepo extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
