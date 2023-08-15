package com.gdu.nhom1.shopproject.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.gdu.nhom1.shopproject.models.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByEmail(String email);
    Optional<User> findByemail(String email);
    @Query(value = "SELECT * FROM user u, users_roles ur, role r WHERE u.id = ur.user_id AND u.email LIKE %:email% AND ur.role_id = r.id AND r.name = 'ROLE_USER'", nativeQuery = true)
    List<User> findByEmailContainingIgnoreCase(@Param("email") String email);
     
    @Query(value = "SELECT * FROM user u, users_roles ur, role r WHERE u.id = ur.user_id AND ur.role_id = r.id AND r.name = 'ROLE_USER'", nativeQuery = true)
    List<User> findAllUserNonAdmin();

}
