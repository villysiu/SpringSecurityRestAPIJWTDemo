package com.villysiu.springsecurityrestapi.controller;

import com.villysiu.springsecurityrestapi.Dto.JwtTokenResponse;
import com.villysiu.springsecurityrestapi.Dto.LoginRequest;
import com.villysiu.springsecurityrestapi.Dto.SignupRequest;
import com.villysiu.springsecurityrestapi.config.JwtAuthenticationFilter;
import com.villysiu.springsecurityrestapi.model.Account;
import com.villysiu.springsecurityrestapi.model.ERole;
import com.villysiu.springsecurityrestapi.model.Role;
import com.villysiu.springsecurityrestapi.repository.AccountRepository;
import com.villysiu.springsecurityrestapi.repository.RoleRepository;
import com.villysiu.springsecurityrestapi.service.AuthenticationService;
import com.villysiu.springsecurityrestapi.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @Autowired
    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);


    @PostMapping("/signin")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest){
        try {
            return new ResponseEntity<>(authenticationService.login(loginRequest), HttpStatus.OK);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return new ResponseEntity<>(e.getMessage(), HttpStatus.UNAUTHORIZED);
        }

    }


    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest, HttpServletRequest request){
        try {
            return new ResponseEntity<>(authenticationService.registerAccount(signupRequest), HttpStatus.CREATED);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return new ResponseEntity<>(e.getMessage(), HttpStatus.UNAUTHORIZED);
        }

    }
//    @PostMapping("/logout")
//    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication){
//        System.out.println("logging out");
//
//        logoutHandler.logout(request, response, authentication);
//
//        request.getSession().removeAttribute("SPRING_SECURITY_CONTEXT");
//        request.getSession().invalidate();
//        SecurityContextHolder.clearContext();
//        return new ResponseEntity<>("Logged out successfully", HttpStatus.OK);
//
//    }
}
