package com.example.controller;

import com.example.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import com.example.dto.ExpenseRequestDTO;
import com.example.model.Expense;
import com.example.repo.ExpenseRepository;
import com.example.repo.UserRepository;

import java.security.Principal;
import java.util.List;

// Keep this controller for REST API endpoints
@RestController
@RequestMapping("/api/expenses")
public class ExpenseController {

    @Autowired
    private ExpenseRepository expenseRepo;

    @Autowired
    private UserRepository userRepo;

    // ✅ Add Expense (uses authenticated user)
    @PostMapping
    public ResponseEntity<?> addExpense(@RequestBody ExpenseRequestDTO dto, Principal principal) {
        try {
            User user = userRepo.findByUsername(principal.getName()).orElse(null);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid user.");
            }

            Expense expense = new Expense();
            expense.setCategory(dto.getCategory());
            expense.setAmount(dto.getAmount());
            expense.setDate(dto.getDate());
            expense.setUser(user);

            Expense savedExpense = expenseRepo.save(expense);
            return ResponseEntity.ok(savedExpense);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: " + e.getMessage());
        }
    }

    // ✅ Update Expense (by ID, if it belongs to the user)
    @PutMapping("/{id}")
    public ResponseEntity<?> updateExpense(@PathVariable Long id, @RequestBody ExpenseRequestDTO dto,
            Principal principal) {
        try {
            User user = userRepo.findByUsername(principal.getName()).orElse(null);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid user.");
            }

            return expenseRepo.findById(id).map(expense -> {
                if (!expense.getUser().getId().equals(user.getId())) {
                    return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Not your expense.");
                }

                expense.setCategory(dto.getCategory());
                expense.setAmount(dto.getAmount());
                expense.setDate(dto.getDate());

                Expense updated = expenseRepo.save(expense);
                return ResponseEntity.ok(updated);
            }).orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).body("Expense not found."));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: " + e.getMessage());
        }
    }

    // ✅ Delete Expense (by ID, if it belongs to the user)
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteExpense(@PathVariable Long id, Principal principal) {
        try {
            User user = userRepo.findByUsername(principal.getName()).orElse(null);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid user.");
            }

            return expenseRepo.findById(id).map(expense -> {
                if (!expense.getUser().getId().equals(user.getId())) {
                    return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Not your expense.");
                }

                expenseRepo.delete(expense);
                return ResponseEntity.ok("Expense deleted successfully.");
            }).orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).body("Expense not found."));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: " + e.getMessage());
        }
    }

    // ✅ Get All Expenses for Logged-in User
    @GetMapping
    public ResponseEntity<?> getUserExpenses(Principal principal) {
        try {
            User user = userRepo.findByUsername(principal.getName()).orElse(null);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid user.");
            }

            List<Expense> expenses = expenseRepo.findByUserId(user.getId());
            return ResponseEntity.ok(expenses);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: " + e.getMessage());
        }
    }
}
