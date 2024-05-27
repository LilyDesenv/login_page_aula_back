package com.example.login_auth_api.controllers;

import com.example.login_auth_api.domain.user.User;
import com.example.login_auth_api.dto.LoginResponseDTO;
import com.example.login_auth_api.dto.LoginResquestDTO;
import com.example.login_auth_api.dto.RegisterRequestDTO;
import com.example.login_auth_api.infra.security.TokenService;
import com.example.login_auth_api.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginResquestDTO body){
        User user = this.repository.findByEmail(body.email())
                .orElseThrow(() -> new RuntimeException("User not found"));
        if (passwordEncoder.matches( body.password(), user.getPassword())){
            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new LoginResponseDTO(user.getName(), token));
        }else{
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequestDTO body){
        Optional<User> findUser = this.repository.findByEmail(body.email());
        if(findUser.isEmpty()){
            User user = new User();
            user.setPassword(passwordEncoder.encode(body.password()));
            user.setName(body.name());
            user.setEmail(body.email());
            this.repository.save(user);

            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new LoginResponseDTO(user.getName(), token));

        }
        return ResponseEntity.badRequest().build();
    }
}
