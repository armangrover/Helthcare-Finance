package com.example.controller;

import com.example.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.example.dto.SecureUserUpdateDTO;
import com.example.repo.UserRepository;

import java.security.Principal;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // ✅ Securely update username and password for the logged-in user
    @PutMapping("/secure-update")
    public ResponseEntity<?> secureUpdateUser(
            @RequestBody SecureUserUpdateDTO dto,
            Principal principal) {

        User user = userRepo.findByUsername(principal.getName())
                .orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found.");
        }

        if (!passwordEncoder.matches(dto.getOldPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Old password is incorrect.");
        }

        user.setUsername(dto.getNewUsername());
        user.setPassword(passwordEncoder.encode(dto.getNewPassword()));
        userRepo.save(user);

        return ResponseEntity.ok("User credentials updated.");
    }

    // ✅ Delete the currently authenticated user
    @DeleteMapping("/delete")
    public ResponseEntity<?> deleteUser(Principal principal) {
        User user = userRepo.findByUsername(principal.getName())
                .orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found.");
        }

        userRepo.delete(user); // deletes associated expenses due to cascade
        return ResponseEntity.ok("User and their expenses deleted successfully.");
    }

    // ✅ Delete all users except 'arman'
    @DeleteMapping("/delete-all-except-arman")
    public ResponseEntity<?> deleteAllExceptArman() {
        userRepo.deleteByUsernameNot("arman");
        return ResponseEntity.ok("All users except 'arman' have been deleted.");
    }
}
