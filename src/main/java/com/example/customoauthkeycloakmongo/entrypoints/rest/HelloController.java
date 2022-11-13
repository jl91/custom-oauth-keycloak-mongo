package com.example.customoauthkeycloakmongo.entrypoints.rest;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class HelloController {

    @GetMapping("health-check")
    public String health() {
        return "I'm Alive";
    }

    @Secured({"admin"})
    @GetMapping("/to-uppercase")
    public String toUppercase(
            @RequestParam("value") final String value
    ) {
        return value.toUpperCase();
    }
}
