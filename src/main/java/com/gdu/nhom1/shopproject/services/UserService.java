package com.gdu.nhom1.shopproject.services;

import java.util.List;
import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.gdu.nhom1.shopproject.dto.UserRegistrationDTO;
import com.gdu.nhom1.shopproject.models.User;
import org.springframework.stereotype.Repository;

@Repository
public interface UserService extends UserDetailsService {
    List<User> findALL();

    User addUser(UserRegistrationDTO registrationDto);

    void removeUserById(long id);

    public Optional<User> getUserById(long id);

    void updateUser(User user);

    User findByEmail(String email);

    List<User> search(String keyword);
    Optional<User> findByName(String email);
}
