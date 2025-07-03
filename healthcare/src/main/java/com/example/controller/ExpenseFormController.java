package com.example.controller;

import com.example.model.Expense;
import com.example.model.User;
import com.example.repo.ExpenseRepository;
import com.example.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;

@Controller
@RequestMapping("/expenses")
public class ExpenseFormController {

    @Autowired
    private ExpenseRepository expenseRepo;

    @Autowired
    private UserRepository userRepo;

    // Handle form submission for adding expense
    @PostMapping("/add")
    public String addExpense(@RequestParam String category,
            @RequestParam Double amount,
            @RequestParam String date,
            Principal principal) {

        try {
            if (principal == null) {
                return "redirect:/login";
            }

            User user = userRepo.findByUsername(principal.getName()).orElse(null);
            if (user == null) {
                return "redirect:/login";
            }

            // Create and save expense
            Expense expense = new Expense();
            expense.setCategory(category);
            expense.setAmount(amount);
            expense.setDate(date);
            expense.setUser(user);

            expenseRepo.save(expense);

            // Redirect to expenses page with success message
            return "redirect:/expenses?success=true";

        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/expenses/add";
        }
    }

    // Handle form submission for updating expense
    @PostMapping("/update/{id}")
    public String updateExpense(@PathVariable Long id,
            @RequestParam String category,
            @RequestParam Double amount,
            @RequestParam String date,
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

            Expense expense = expenseRepo.findById(id).orElse(null);
            if (expense == null) {
                return "redirect:/expenses?error=Expense not found!";
            }

            // Check if expense belongs to user
            if (!expense.getUser().getId().equals(user.getId())) {
                return "redirect:/expenses?error=You don't have permission to edit this expense!";
            }

            // Validate inputs
            if (category == null || category.trim().isEmpty()) {
                return "redirect:/expenses/edit/" + id + "?error=Category is required!";
            }

            if (amount == null || amount <= 0) {
                return "redirect:/expenses/edit/" + id + "?error=Amount must be greater than 0!";
            }

            if (date == null || date.trim().isEmpty()) {
                return "redirect:/expenses/edit/" + id + "?error=Date is required!";
            }

            expense.setCategory(category.trim());
            expense.setAmount(amount);
            expense.setDate(date.trim());

            expenseRepo.save(expense);
            return "redirect:/expenses?success=true";

        } catch (Exception e) {
            e.printStackTrace(); // Log the full error for debugging
            return "redirect:/expenses/edit/" + id + "?error=" + e.getMessage();
        }
    }

    // Handle form submission for deleting expense
    @PostMapping("/delete/{id}")
    public String deleteExpense(@PathVariable Long id,
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

            Expense expense = expenseRepo.findById(id).orElse(null);
            if (expense == null) {
                return "redirect:/expenses?error=Expense not found!";
            }

            // Check if expense belongs to user
            if (!expense.getUser().getId().equals(user.getId())) {
                return "redirect:/expenses?error=You don't have permission to delete this expense!";
            }

            expenseRepo.delete(expense);
            return "redirect:/expenses?success=deleted";

        } catch (Exception e) {
            e.printStackTrace(); // Log the full error for debugging
            return "redirect:/expenses?error=" + e.getMessage();
        }
    }
}