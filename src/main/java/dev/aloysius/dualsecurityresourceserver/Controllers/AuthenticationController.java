package dev.aloysius.dualsecurityresourceserver.Controllers;

import dev.aloysius.dualsecurityresourceserver.Models.AppUser;
import dev.aloysius.dualsecurityresourceserver.Service.TokenService;
import dev.aloysius.dualsecurityresourceserver.Service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auth")
public class AuthenticationController {

    private final UserService userService;
    private final TokenService tokenService;

    public AuthenticationController(UserService userService, TokenService tokenService) {
        this.userService = userService;
        this.tokenService = tokenService;
    }

    @PostMapping("/register")
    public void registerUser(@RequestBody AppUser appUser){
        userService.addUsers(appUser);
    }

    @GetMapping("/authenticate")
    public String authenticate(Authentication authentication){
        return tokenService.generateToken(authentication);
    }
    @GetMapping("/greet")
    public String greet(Authentication authentication){
        return String.format("hello user with username : %s, welcome to this page", authentication.getName());
    }

    @ExceptionHandler
    public ResponseEntity<?> handleException(Exception ex){
        return ResponseEntity.badRequest().body(ex.getMessage());
    }
}
