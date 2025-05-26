package com.restaurant.management.config.security;

import com.restaurant.management.model.Customer;
import com.restaurant.management.model.Employee;
import com.restaurant.management.service.CustomerService;
import com.restaurant.management.service.EmployeeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private EmployeeService employeeService;
    @Autowired
    private CustomerService customerService;
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        System.out.println("Email login:::" + email);
        Employee employee = employeeService.getEmployeeByEmail(email);
        if (employee != null) {
            return new CustomUserDetails(
                    employee.getEmail(),
                    employee.getPassword(),
                    "ROLE_" + employee.getPosition(),
                    employee.getId()
            );
        }

        Optional<Customer> customer = customerService.getCustomerByEmail(email);
        if (customer.isPresent()) {
            return new CustomUserDetails(
                    customer.get().getEmail(),
                    customer.get().getPassword(),
                    "ROLE_CUSTOMER",
                    customer.get().getCustomerId()
            );
        }

        throw new UsernameNotFoundException("User not found with email: " + email);
    }
}