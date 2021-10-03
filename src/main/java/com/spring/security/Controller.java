package com.spring.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {

    @GetMapping("/")
    public String index(){
        return "home";
    }

    @GetMapping("/user")
    public String user(){
        return "user";
    }

    @GetMapping("/sample")
    public String sample(){
        return "sample";
    }

    @GetMapping("/admin/pay")
    public String adminPay(){
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin(){
        return "admin";
    }

    @GetMapping("/login")
    public String login(){
        return "login";
    }

    @GetMapping("/denied")
    public String denied(){
        return "denied";
    }
}
