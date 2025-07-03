package com.example.controller;

import com.example.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import com.example.repo.UserRepository;
import com.example.service.ChartService;
import com.example.repo.ExpenseRepository;

import java.security.Principal;
import java.util.Optional;

@RestController
@RequestMapping("/api/charts")
public class ChartController {

    @Autowired
    private ChartService chartService;

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private ExpenseRepository expenseRepo;

    // ✅ Pie chart for logged-in user
    @GetMapping("/pie")
    public ResponseEntity<byte[]> getCategoryPieChart(Principal principal) {
        try {
            Optional<User> optionalUser = userRepo.findByUsername(principal.getName());
            if (optionalUser.isEmpty()) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            User user = optionalUser.get();
            byte[] chart = chartService.generateCategoryPieChart(user.getId());

            if (chart == null || chart.length == 0) {
                return new ResponseEntity<>(HttpStatus.NO_CONTENT);
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.IMAGE_PNG);
            return new ResponseEntity<>(chart, headers, HttpStatus.OK);

        } catch (Exception e) {
            e.printStackTrace(); // Log actual error to console
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // ✅ Bar chart for logged-in user
    @GetMapping("/bar")
    public ResponseEntity<byte[]> getMonthlyBarChart(Principal principal) {
        try {
            Optional<User> optionalUser = userRepo.findByUsername(principal.getName());
            if (optionalUser.isEmpty()) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            User user = optionalUser.get();
            byte[] chart = chartService.generateMonthlyBarChart(user.getId());

            if (chart == null || chart.length == 0) {
                return new ResponseEntity<>(HttpStatus.NO_CONTENT);
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.IMAGE_PNG);
            return new ResponseEntity<>(chart, headers, HttpStatus.OK);

        } catch (Exception e) {
            e.printStackTrace(); // Log actual error to console
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // JSON data for interactive charts
    @GetMapping("/data")
    public java.util.Map<String, Object> getChartData(Principal principal) {
        java.util.Map<String, Object> result = new java.util.HashMap<>();
        Optional<User> optionalUser = userRepo.findByUsername(principal.getName());
        if (optionalUser.isEmpty()) {
            result.put("labels", java.util.Collections.emptyList());
            result.put("values", java.util.Collections.emptyList());
            return result;
        }
        User user = optionalUser.get();
        java.util.List<com.example.model.Expense> expenses = expenseRepo.findByUserId(user.getId());
        java.util.Map<String, Double> categoryTotals = new java.util.HashMap<>();
        for (com.example.model.Expense e : expenses) {
            categoryTotals.put(e.getCategory(), categoryTotals.getOrDefault(e.getCategory(), 0.0) + e.getAmount());
        }
        result.put("labels", new java.util.ArrayList<>(categoryTotals.keySet()));
        result.put("values", new java.util.ArrayList<>(categoryTotals.values()));
        return result;
    }
}
