package com.villysiu.springsecurityrestapi.controller;

import com.villysiu.springsecurityrestapi.Dto.LoginRequest;
import com.villysiu.springsecurityrestapi.Dto.SignupRequest;
import com.villysiu.springsecurityrestapi.model.Role;
import com.villysiu.springsecurityrestapi.model.User;
import com.villysiu.springsecurityrestapi.repository.RoleRepository;
import com.villysiu.springsecurityrestapi.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
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

import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    @Autowired
    private  AuthenticationManager authenticationManager;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;


    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest, HttpServletRequest request){
        System.out.println(loginRequest.toString());
        Authentication authenticationRequest = new UsernamePasswordAuthenticationToken(
                loginRequest.getEmail(), loginRequest.getPassword());
        Authentication authenticationResponse = authenticationManager.authenticate(authenticationRequest);

        //Add failure excetpio
        SecurityContextHolder.getContext().setAuthentication(authenticationResponse);

        HttpSession session = request.getSession();
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
        return new ResponseEntity<>("User signed-in successfully!.", HttpStatus.OK);
    }
//    https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/index.html#servlet-authentication-unpwd-input
//    @PostMapping("/login")
//    public ResponseEntity<Void> login(@RequestBody LoginRequest loginRequest) {
//        Authentication authenticationRequest =
//                UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(), loginRequest.password());
//        Authentication authenticationResponse =
//                this.authenticationManager.authenticate(authenticationRequest);
//        // ...
//    }


    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest, HttpServletRequest request){

        // add check for email exists in DB
        if(userRepository.existsByEmail(signupRequest.getEmail())){
            return new ResponseEntity<>("Email already used!", HttpStatus.BAD_REQUEST);
        }


        // create user object
        User user = new User();
        user.setName(signupRequest.getName());
        user.setEmail(signupRequest.getEmail());
        user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));

        Role role = roleRepository.findByName("ROLE_USER");
        user.setRoles(Set.of(role));

        userRepository.save(user);

        return new ResponseEntity<>("User registered successfully", HttpStatus.OK);

    }
}
