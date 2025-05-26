package com.restaurant.management.config.security;

import com.restaurant.management.controller.AccountController;
import com.restaurant.management.model.Customer;
import com.restaurant.management.model.Employee;
import com.restaurant.management.service.CustomerService;
import com.restaurant.management.service.EmployeeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private EmployeeService employeeService;

    @Autowired
    private CustomerService customerService;

    @Autowired
    private AccountController accountController;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        System.out.println("Checking user: " + email); // Debug
        if (accountController.isAccountLocked(email)) {
            System.out.println("User " + email + " is locked"); // Debug
            throw new UsernameNotFoundException("Tài khoản bị khóa. Vui lòng thử lại sau 2 phút.");
        }

        System.out.println("Email đăng nhập: " + email);

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

        throw new UsernameNotFoundException("Không tìm thấy người dùng với email: " + email);
    }
}