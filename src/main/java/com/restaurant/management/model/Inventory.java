package com.restaurant.management.model;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.util.ArrayList;
import java.util.List;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class Inventory {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long inventoryId;

    String itemName;
    String description;
    String unit;//don vi tinh
    int quantity;
    Double unitPrice;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name="supplier_id", nullable=false)
    Supplier supplier;
}
