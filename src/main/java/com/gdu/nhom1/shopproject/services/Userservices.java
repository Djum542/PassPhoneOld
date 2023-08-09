package com.gdu.nhom1.shopproject.services;

import com.gdu.nhom1.shopproject.models.User;
import com.gdu.nhom1.shopproject.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@Transactional
public class Userservices {
    private UserRepository repo;
    private PasswordEncoder passwordEncoder;
    public User save(User user){
        // lay password nhap vao
        String rawpassword = user.getPassword();
        String encodePassword = passwordEncoder.encode(rawpassword);
        return repo.save(user);
    }
}
