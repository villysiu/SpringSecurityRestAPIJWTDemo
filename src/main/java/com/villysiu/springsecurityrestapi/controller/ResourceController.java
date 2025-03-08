package com.villysiu.springsecurityrestapi.controller;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {


    @GetMapping("/secret_resource")
    public ResponseEntity<String> secret(){
        return new ResponseEntity<>("You are viewing my secret" , HttpStatus.OK);
    }
    @GetMapping("/public_resource")
    public ResponseEntity<String> nosecret(){
        // assuming no existing user

        return new ResponseEntity<>("You are in public area", HttpStatus.OK);
    }
}


