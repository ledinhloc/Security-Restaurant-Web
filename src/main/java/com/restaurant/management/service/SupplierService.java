package com.restaurant.management.service;

import com.restaurant.management.model.Customer;
import com.restaurant.management.model.Supplier;
import com.restaurant.management.repository.SupplierRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SupplierService {
    @Autowired
    SupplierRepository supplierRepository;

    public List<Supplier> getAllSuppliers() {
        return supplierRepository.findAll();
    }
    public Page<Supplier> getSuppliersWithPagination(int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size);
        return supplierRepository.findAll(pageRequest);
    }


    public Supplier saveSupplier(Supplier supplier) {return supplierRepository.save(supplier);}

    public  void deleteSupplier(Long id) {
        supplierRepository.deleteById(id);
    }

    public Supplier updateSupplier(Supplier supplier) {
        Supplier existingSupplier = supplierRepository.findById(supplier.getSupplierId())
                .orElseThrow(() -> new RuntimeException("Customer not found with id: "));

        existingSupplier.setName(supplier.getName());
        existingSupplier.setPhone(supplier.getPhone());

        existingSupplier.setEmail(supplier.getEmail());
        existingSupplier.setAddress(supplier.getAddress());

        existingSupplier.setNotes(supplier.getNotes());

        return supplierRepository.save(existingSupplier);
    }

    public Supplier getSupplierById(Long id) {
        return supplierRepository.findById(id).orElse(null);
    }
}
