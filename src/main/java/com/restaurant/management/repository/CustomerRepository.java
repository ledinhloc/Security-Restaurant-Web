package com.restaurant.management.repository;

import com.restaurant.management.model.Customer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CustomerRepository extends JpaRepository<Customer, Long> {
    Optional<Customer> findByEmail(String email);

    Customer findByPhone(String phoneNumber);
    
    @Query("SELECT c.customerId FROM Customer c WHERE c.email = :email")
    Long getCustomerIdByEmail(@Param("email") String email);
}
