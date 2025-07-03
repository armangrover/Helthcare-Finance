package com.example.model;

import jakarta.persistence.*;
import lombok.*;

@Entity // (1) Declares it as a JPA Entity
@Table(name = "expenses") // (2) Mapped to 'expenses' table
@Data
@NoArgsConstructor
@AllArgsConstructor

public class Expense {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; // (3) Primary key

    private String category; // (4) E.g., 'medication', 'consultation'
    private Double amount; // (5) Expense amount
    private String date; // (6) Date as string (format: yyyy-MM-dd)

    @ManyToOne // (7) Many expenses → one user
    @JoinColumn(name = "user_id") // (8) Foreign key column
    private User user; // (9) The user who owns this expense
}
