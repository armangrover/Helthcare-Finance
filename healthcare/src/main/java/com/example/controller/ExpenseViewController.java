package com.example.controller;

import com.example.model.Expense;
import com.example.model.User;
import com.example.repo.ExpenseRepository;
import com.example.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;
import java.util.List;

@Controller
public class ExpenseViewController {

    @Autowired
    private ExpenseRepository expenseRepo;

    @Autowired
    private UserRepository userRepo;

    @GetMapping("/expenses/view")
    public String viewUserExpenses(Model model, Principal principal) {
        // Check if the user is authenticated
        if (principal == null || principal.getName() == null) {
            return "redirect:/login";
        }

        // Fetch user by username
        User user = userRepo.findByUsername(principal.getName()).orElse(null);
        if (user == null) {
            return "redirect:/login";
        }

        // Fetch expenses by user ID
        List<Expense> expenses = expenseRepo.findByUserId(user.getId());

        // Add expenses to the model
        model.addAttribute("expenses", expenses);
        model.addAttribute("username", user.getUsername());

        return "expenses"; // Thymeleaf template: resources/templates/expenses.html
    }
}
