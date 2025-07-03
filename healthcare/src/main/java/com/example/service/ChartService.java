package com.example.service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.model.Expense;
import com.example.repo.ExpenseRepository;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;

import org.knowm.xchart.*;
@Service
public class ChartService {

    @Autowired
    private ExpenseRepository expenseRepository;

    public byte[] generateCategoryPieChart(Long userId) throws IOException {
        List<Expense> expenses = expenseRepository.findByUserId(userId);

        Map<String, Double> categoryTotals = new HashMap<>();
        for (Expense e : expenses) {
            categoryTotals.put(e.getCategory(), categoryTotals.getOrDefault(e.getCategory(), 0.0) + e.getAmount());
        }

        PieChart chart = new PieChartBuilder().width(600).height(400).title("Expenses by Category").build();

        for (Map.Entry<String, Double> entry : categoryTotals.entrySet()) {
            chart.addSeries(entry.getKey(), entry.getValue());
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        BitmapEncoder.saveBitmap(chart, baos, BitmapEncoder.BitmapFormat.PNG);
        return baos.toByteArray();
    }

    public byte[] generateMonthlyBarChart(Long userId) throws IOException {
        List<Expense> expenses = expenseRepository.findByUserId(userId);

        Map<String, Double> monthlyTotals = new TreeMap<>();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM");

        for (Expense e : expenses) {
            LocalDate date = LocalDate.parse(e.getDate()); // ensure date is stored in ISO format (yyyy-MM-dd)
            String monthKey = date.format(formatter);
            monthlyTotals.put(monthKey, monthlyTotals.getOrDefault(monthKey, 0.0) + e.getAmount());
        }

        CategoryChart chart = new CategoryChartBuilder().width(800).height(400).title("Monthly Expenses")
                .xAxisTitle("Month").yAxisTitle("Amount").build();
        chart.addSeries("Expenses", new ArrayList<>(monthlyTotals.keySet()), new ArrayList<>(monthlyTotals.values()));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        BitmapEncoder.saveBitmap(chart, baos, BitmapEncoder.BitmapFormat.PNG);
        return baos.toByteArray();
    }
}
