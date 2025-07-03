package com.example.controller;

import com.example.model.Expense;
import com.example.model.User;
import com.example.repo.ExpenseRepository;
import com.example.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.util.List;
import java.util.Optional;
import jakarta.servlet.http.HttpSession;

@Controller
public class ViewController {

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private ExpenseRepository expenseRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    @GetMapping("/dashboard")
    public String dashboardPage(Model model, Principal principal) {
        try {
            if (principal == null) {
                return "redirect:/login";
            }

            Optional<User> userOpt = userRepo.findByUsername(principal.getName());
            if (userOpt.isEmpty()) {
                return "redirect:/login";
            }

            User user = userOpt.get();
            model.addAttribute("username", user.getUsername());

            // Get user's expenses for summary using the same approach as expenses page
            List<Expense> userExpenses;
            try {
                userExpenses = expenseRepo.findExpensesByUserId(user.getId());
            } catch (Exception e) {
                // Fallback: get all expenses and filter
                List<Expense> allExpenses = expenseRepo.findAll();
                userExpenses = allExpenses.stream()
                        .filter(expense -> expense.getUser() != null && expense.getUser().getId().equals(user.getId()))
                        .toList();
            }

            model.addAttribute("totalExpenses", userExpenses.size());
            double totalAmount = userExpenses.stream().mapToDouble(Expense::getAmount).sum();
            model.addAttribute("totalAmount", totalAmount);

            return "dashboard";
        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("errorMessage", "Error loading dashboard: " + e.getMessage());
            return "error";
        }
    }

    @GetMapping("/expenses")
    public String expensesPage(@RequestParam(required = false) String success,
            @RequestParam(required = false) String error,
            Model model,
            Principal principal) {
        try {
            if (principal == null) {
                return "redirect:/login";
            }

            Optional<User> userOpt = userRepo.findByUsername(principal.getName());
            if (userOpt.isEmpty()) {
                return "redirect:/login";
            }

            User user = userOpt.get();
            System.out.println("Loading expenses for user: " + user.getUsername() + " (ID: " + user.getId() + ")");

            // Try the custom query method first
            List<Expense> userExpenses;
            try {
                userExpenses = expenseRepo.findExpensesByUserId(user.getId());
                System.out.println("Found " + userExpenses.size() + " expenses using custom query");
            } catch (Exception e) {
                System.out.println("Custom query failed, trying fallback method: " + e.getMessage());
                // Fallback: get all expenses and filter
                List<Expense> allExpenses = expenseRepo.findAll();
                userExpenses = allExpenses.stream()
                        .filter(expense -> expense.getUser() != null && expense.getUser().getId().equals(user.getId()))
                        .toList();
                System.out.println("Found " + userExpenses.size() + " expenses using fallback method");
            }

            model.addAttribute("expenses", userExpenses);
            model.addAttribute("username", user.getUsername());

            // Handle success/error messages from query parameters
            if (success != null && !success.isEmpty()) {
                if (success.equals("true")) {
                    model.addAttribute("success", "Expense added successfully!");
                } else if (success.equals("deleted")) {
                    model.addAttribute("success", "Expense deleted successfully!");
                } else if (success.equals("updated")) {
                    model.addAttribute("success", "Expense updated successfully!");
                }
            }
            if (error != null && !error.isEmpty()) {
                model.addAttribute("error", error);
            }

            double totalAmount = userExpenses.stream().mapToDouble(Expense::getAmount).sum();
            model.addAttribute("totalAmount", totalAmount);

            return "expenses";
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Error in expenses page: " + e.getMessage());
            model.addAttribute("errorMessage", "Error loading expenses: " + e.getMessage());
            return "error";
        }
    }

    @GetMapping("/expenses/add")
    public String addExpensePage(@RequestParam(required = false) String error,
            Model model,
            Principal principal) {
        if (principal == null) {
            return "redirect:/login";
        }

        Optional<User> userOpt = userRepo.findByUsername(principal.getName());
        if (userOpt.isEmpty()) {
            return "redirect:/login";
        }

        model.addAttribute("username", userOpt.get().getUsername());

        // Handle error message from query parameter
        if (error != null && !error.isEmpty()) {
            model.addAttribute("error", error);
        }

        return "add-expense";
    }

    @GetMapping("/expenses/edit/{id}")
    public String editExpensePage(@PathVariable Long id,
            @RequestParam(required = false) String error,
            Model model,
            Principal principal) {
        if (principal == null) {
            return "redirect:/login";
        }

        Optional<User> userOpt = userRepo.findByUsername(principal.getName());
        if (userOpt.isEmpty()) {
            return "redirect:/login";
        }

        User user = userOpt.get();
        Optional<Expense> expenseOpt = expenseRepo.findById(id);

        if (expenseOpt.isEmpty()) {
            model.addAttribute("errorMessage", "Expense not found");
            return "error";
        }

        Expense expense = expenseOpt.get();

        // Check if the expense belongs to the current user
        if (!expense.getUser().getId().equals(user.getId())) {
            model.addAttribute("errorMessage", "You don't have permission to edit this expense");
            return "error";
        }

        model.addAttribute("expense", expense);
        model.addAttribute("username", user.getUsername());

        // Handle error message from query parameter
        if (error != null && !error.isEmpty()) {
            model.addAttribute("error", error);
        }

        return "edit-expense";
    }

    @GetMapping("/expenses/delete/{id}")
    public String deleteExpensePage(@PathVariable Long id, Model model, Principal principal) {
        if (principal == null) {
            return "redirect:/login";
        }

        Optional<User> userOpt = userRepo.findByUsername(principal.getName());
        if (userOpt.isEmpty()) {
            return "redirect:/login";
        }

        User user = userOpt.get();
        Optional<Expense> expenseOpt = expenseRepo.findById(id);

        if (expenseOpt.isEmpty()) {
            model.addAttribute("errorMessage", "Expense not found");
            return "error";
        }

        Expense expense = expenseOpt.get();

        // Check if the expense belongs to the current user
        if (!expense.getUser().getId().equals(user.getId())) {
            model.addAttribute("errorMessage", "You don't have permission to delete this expense");
            return "error";
        }

        // Delete the expense
        expenseRepo.delete(expense);

        // Redirect back to expenses page
        return "redirect:/expenses";
    }

    @GetMapping("/profile")
    public String profilePage(Model model, Principal principal) {
        if (principal == null) {
            return "redirect:/login";
        }

        Optional<User> userOpt = userRepo.findByUsername(principal.getName());
        if (userOpt.isEmpty()) {
            return "redirect:/login";
        }

        User user = userOpt.get();
        model.addAttribute("user", user);
        model.addAttribute("username", user.getUsername());

        return "profile";
    }

    @GetMapping("/logout")
    public String logoutPage() {
        return "redirect:/login";
    }

    @GetMapping("/error")
    public String errorPage(@RequestParam(required = false) String message, Model model) {
        model.addAttribute("errorMessage", message != null ? message : "An unexpected error occurred");
        return "error";
    }

    @PostMapping("/register")
    public String registerForm(
            @RequestParam String username,
            @RequestParam String email,
            @RequestParam String password,
            RedirectAttributes redirectAttributes) {
        if (userRepo.findByUsername(username).isPresent()) {
            redirectAttributes.addFlashAttribute("error", "Username already exists!");
            return "redirect:/register";
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        userRepo.save(user);

        // Show a success page that redirects to login
        return "register-success";
    }
}