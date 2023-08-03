package dev.aloysius.dualsecurityresourceserver.Service;

import dev.aloysius.dualsecurityresourceserver.Models.AppUser;
import dev.aloysius.dualsecurityresourceserver.Repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public void addUsers(AppUser appUser) {

        boolean present = userRepository.findByEmail(appUser.getEmail()).isPresent();
        if(present){
           throw  new RuntimeException();
        }
        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        userRepository.save(appUser);

    }
}
