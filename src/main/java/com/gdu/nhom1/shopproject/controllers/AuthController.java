package com.gdu.nhom1.shopproject.controllers;



import com.gdu.nhom1.shopproject.dto.AuthRequest;
import com.gdu.nhom1.shopproject.jwt.JwtTokenUtil;
import com.gdu.nhom1.shopproject.models.AuthReponse;
import com.gdu.nhom1.shopproject.models.User;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import javax.validation.Valid;


@Controller
public class AuthController {
    AuthenticationManager authManager;
    JwtTokenUtil jwtUtil;
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/403")
    public String errorPage() {
        return "403";
    }
    @PostMapping ("/auth/logins")
    public ResponseEntity<?> loginauth(@RequestBody @Valid AuthRequest request){
        try {
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );
            User user = (User) authentication.getPrincipal();
            String accessToken = jwtUtil.generaAccessToken(user);
            AuthReponse reponse = new AuthReponse(user.getEmail(),accessToken);
            return ResponseEntity.ok().body(reponse);
        }catch (BadCredentialsException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
