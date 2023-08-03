package dev.aloysius.dualsecurityresourceserver.Controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/home")
public class HomeController {

    @GetMapping("/welcome")
    public String welcome(Authentication authentication){
        return String.format("welcome to the home page, user with username %s", authentication.getName() );
    }

    @ExceptionHandler
    public ResponseEntity<?> handleException(Exception ex){
        return ResponseEntity.badRequest().body(ex.getMessage());
    }
}
