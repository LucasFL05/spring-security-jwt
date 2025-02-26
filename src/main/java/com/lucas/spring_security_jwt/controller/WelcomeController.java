package com.lucas.spring_security_jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class WelcomeController {
    @GetMapping
    public String welcome(){
        return "Welcome to My Spring Boot Web API";
    }
    @GetMapping("/user")
    public String users() {
        return "Authorized user";
    }
    @GetMapping("/admin")
    public String managers() {
        return "Authorized admin";
    }
}