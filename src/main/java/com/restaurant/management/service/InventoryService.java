package com.restaurant.management.service;

import com.restaurant.management.model.Customer;
import com.restaurant.management.model.Inventory;
import com.restaurant.management.model.Supplier;
import com.restaurant.management.repository.CustomerRepository;
import com.restaurant.management.repository.InventoryRepository;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.Mapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Service
public class InventoryService {
    @Autowired
    public InventoryRepository inventoryRepository;

    @Autowired
    public SupplierService supplierService;

    public List<Inventory> getAllInventory() {
        return inventoryRepository.findAll();
    }

    public Page<Inventory> getInventoryWithPagination(int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size);
        return inventoryRepository.findAll(pageRequest);
    }

    public void deleteInventory(Long id) {
        inventoryRepository.deleteById(id);
    }

    public Inventory saveInventory(Inventory inventory) {
        Supplier supplier = supplierService.getSupplierById(inventory.getSupplier().getSupplierId());
        inventory.setSupplier(supplier);
        return inventoryRepository.save(inventory);
    }

    public Inventory updateInventory(Inventory inventory, Long id) {
        Inventory existingInventory = inventoryRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Inventory not found with id: " + inventory.getInventoryId()));

       // BeanUtils.copyProperties(inventory, existingInventory, "inventoryId"); // Bỏ qua `inventoryId` n
        existingInventory.setUnit(inventory.getUnit());
        existingInventory.setQuantity(inventory.getQuantity());
        existingInventory.setDescription(inventory.getDescription());

        Supplier supplier = supplierService.getSupplierById(existingInventory.getSupplier().getSupplierId());

        existingInventory.setSupplier(supplier);
        existingInventory.setItemName(inventory.getItemName());
        existingInventory.setUnitPrice(inventory.getUnitPrice());

        return inventoryRepository.save(existingInventory);
    }

    public Inventory getById(Long id) {
        return inventoryRepository.findById(id).orElseThrow(() -> new RuntimeException("Inventory not found with id: " + id));
    }

    public List<Object[]> getInventoryData() {
        return inventoryRepository.getInventoryData();
    }
}
