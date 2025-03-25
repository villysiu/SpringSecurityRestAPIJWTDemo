package com.villysiu.springsecurityrestapi.service;

import com.villysiu.springsecurityrestapi.Dto.LoginRequest;
import com.villysiu.springsecurityrestapi.Dto.SignupRequest;
import com.villysiu.springsecurityrestapi.model.Account;
import com.villysiu.springsecurityrestapi.model.ERole;
import com.villysiu.springsecurityrestapi.model.Role;
import com.villysiu.springsecurityrestapi.repository.AccountRepository;
import com.villysiu.springsecurityrestapi.repository.RoleRepository;
import jakarta.persistence.EntityExistsException;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final AccountRepository accountRepository;
    private final JwtService jwtService;
    private final RoleRepository roleRepository;

    public AuthenticationService(AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, AccountRepository accountRepository, JwtService jwtService, RoleRepository roleRepository) {
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.accountRepository = accountRepository;
        this.jwtService = jwtService;
        this.roleRepository = roleRepository;
    }
    public String login(LoginRequest loginRequest, HttpServletResponse response) {

        Authentication authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.getEmail(), loginRequest.getPassword());
        Authentication authenticationResponse = this.authenticationManager.authenticate(authenticationRequest);

        SecurityContextHolder.getContext().setAuthentication(authenticationResponse);

        jwtService.generateToken(loginRequest.getEmail(), response);


        UserDetails userDetails = (UserDetails) authenticationResponse.getPrincipal();

//        System.out.println("email: " + email);
        return userDetails.getUsername();
    }
    public void registerAccount(SignupRequest signupRequest){

        if(accountRepository.existsByEmail(signupRequest.getEmail())){
            throw new EntityExistsException("Email already used");
        }

        // create user object
        Account account = new Account(signupRequest.getName(), signupRequest.getEmail(), passwordEncoder.encode(signupRequest.getPassword()));
        Role role = roleRepository.findByErole(ERole.ROLE_USER).orElse(null);

        System.out.println(role);
        account.setRoles(Collections.singleton(role));
        accountRepository.save(account);

    }
    public void logoutUser(HttpServletResponse response){
        jwtService.removeTokenFromCookie(response);
    }
}
