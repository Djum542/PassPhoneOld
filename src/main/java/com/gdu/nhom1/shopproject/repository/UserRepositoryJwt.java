package com.gdu.nhom1.shopproject.repository;

import java.util.Optional;

import com.gdu.nhom1.shopproject.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepositoryJwt extends JpaRepository<User, Integer> {
	
	Optional<User> findByEmail(String email);
	
}
