package com.example.dto;

import lombok.Data;

@Data
public class ExpenseRequestDTO {
    private String category;
    private Double amount;
    private String date; // Format: yyyy-MM-dd
}
