package com.villysiu.springsecurityrestapi.service;

import com.villysiu.springsecurityrestapi.Dto.JwtTokenResponse;
import com.villysiu.springsecurityrestapi.Dto.LoginRequest;
import com.villysiu.springsecurityrestapi.Dto.SignupRequest;
import com.villysiu.springsecurityrestapi.model.Account;
import com.villysiu.springsecurityrestapi.model.ERole;
import com.villysiu.springsecurityrestapi.model.Role;
import com.villysiu.springsecurityrestapi.repository.AccountRepository;
import com.villysiu.springsecurityrestapi.repository.RoleRepository;
import jakarta.persistence.EntityExistsException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class AuthenticationService {
    @Autowired
    private final AuthenticationManager authenticationManager;

    @Autowired
    private final PasswordEncoder passwordEncoder;

    @Autowired
    private final AccountRepository accountRepository;


    @Autowired
    private final JwtService jwtService;
    @Autowired
    private RoleRepository roleRepository;

    public AuthenticationService(AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, AccountRepository accountRepository,  JwtService jwtService) {
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.accountRepository = accountRepository;
        this.jwtService = jwtService;
    }
    public JwtTokenResponse login(LoginRequest loginRequest) {

        Authentication authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.getEmail(), loginRequest.getPassword());
        Authentication authenticationResponse = this.authenticationManager.authenticate(authenticationRequest);

        SecurityContextHolder.getContext().setAuthentication(authenticationResponse);

        String jwt = jwtService.generateToken(loginRequest.getEmail());
        System.out.println(jwt);

        //look up sending the token in response cookie to send in header
        // or http session?
        return JwtTokenResponse.builder().token(jwt).build();
    }
    public Account registerAccount(SignupRequest signupRequest){
        System.out.println("sign up");
        // add check for email exists in DB
        if(accountRepository.existsByEmail(signupRequest.getEmail())){
            throw new EntityExistsException("Email already used");
        }


        // create user object
        Account account = new Account(signupRequest.getName(), signupRequest.getEmail(), passwordEncoder.encode(signupRequest.getPassword()));
        Role role = roleRepository.findByErole(ERole.ROLE_USER).orElse(
                roleRepository.save( new Role(ERole.ROLE_USER))
        );
        account.setRoles(Collections.singleton(role));

        return accountRepository.save(account);


    }
}
