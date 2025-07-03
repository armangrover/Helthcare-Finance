package com.example.controller;

import com.example.model.User;
import com.example.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;

@Controller
@RequestMapping("/users")
public class UserFormController {

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // Handle form submission for updating user profile
    @PostMapping("/update")
    public String updateProfile(@RequestParam String username,
            @RequestParam String email,
            @RequestParam(required = false) String password,
            Principal principal,
            RedirectAttributes redirectAttributes) {
        try {
            if (principal == null) {
                return "redirect:/login";
            }

            User user = userRepo.findByUsername(principal.getName()).orElse(null);
            if (user == null) {
                return "redirect:/login";
            }

            // Check if username is already taken by another user
            if (!username.equals(user.getUsername())) {
                if (userRepo.findByUsername(username).isPresent()) {
                    redirectAttributes.addFlashAttribute("error", "Username already exists!");
                    return "redirect:/profile";
                }
            }

            user.setUsername(username);
            user.setEmail(email);

            // Update password only if provided
            if (password != null && !password.trim().isEmpty()) {
                user.setPassword(passwordEncoder.encode(password));
            }

            userRepo.save(user);
            redirectAttributes.addFlashAttribute("success", "Profile updated successfully!");

        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Error updating profile: " + e.getMessage());
        }

        return "redirect:/profile";
    }

    // Handle form submission for deleting user account
    @PostMapping("/delete")
    public String deleteAccount(Principal principal,
            RedirectAttributes redirectAttributes) {
        try {
            if (principal == null) {
                return "redirect:/login";
            }

            User user = userRepo.findByUsername(principal.getName()).orElse(null);
            if (user == null) {
                return "redirect:/login";
            }

            userRepo.delete(user);
            redirectAttributes.addFlashAttribute("success", "Account deleted successfully!");

        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Error deleting account: " + e.getMessage());
            return "redirect:/profile";
        }

        return "redirect:/login";
    }
}