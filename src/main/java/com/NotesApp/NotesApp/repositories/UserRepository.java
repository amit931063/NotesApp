package com.NotesApp.NotesApp.repositories;
import com.NotesApp.NotesApp.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface UserRepository  extends JpaRepository<User,Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    // change the code - 22/07/25 //
//    @Bean
//    default CommandLineRunner run(RoleRepository roleRepository) {
//        return args -> {
//            if (roleRepository.findAll().isEmpty()) {
//                roleRepository.save(new Role(ERole.ROLE_USER));
//                roleRepository.save(new Role(ERole.ROLE_ADMIN));
//            }
//        };
//    }
}
