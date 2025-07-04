package com.example.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.example.dto.UserRequestDTO;
import com.example.model.User;
import com.example.repo.UserRepository;

import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<String> register(@ModelAttribute UserRequestDTO request) {
        System.out
                .println("Register attempt for username: " + request.getUsername() + ", email: " + request.getEmail());

        if (userRepo.findByUsername(request.getUsername()).isPresent()) {
            System.out.println("Registration failed: Username already exists: " + request.getUsername());
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists!");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());

        // 👇 Encode password before saving
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        userRepo.save(user);

        System.out.println("Registration successful for user: " + request.getUsername());

        return ResponseEntity.ok("User registered successfully!");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String username,
            @RequestParam String password,
            HttpSession session) {

        System.out.println("Login attempt for username: " + username);

        User user = userRepo.findByUsername(username).orElse(null);

        // 👇 Use encoder to verify password
        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            System.out.println("Login failed: Invalid credentials for user: " + username);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials!");
        }

        // Store user in session
        session.setAttribute("userId", user.getId());
        session.setAttribute("username", user.getUsername());

        System.out.println("Login successful for user: " + username + " (ID: " + user.getId() + ")");

        return ResponseEntity.ok("Login successful!");
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpSession session) {
        session.invalidate();
        return ResponseEntity.ok("Logged out successfully!");
    }

    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("API is working!");
    }
}
