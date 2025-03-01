package com.restaurant.management.service;

import com.restaurant.management.model.Employee;
import com.restaurant.management.repository.EmployeeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Service
public class EmployeeService {
    @Autowired
    private EmployeeRepository employeeRepository;

    @Autowired
    private StorageService storageService;

    public List<Employee> getAllEmployees() {
        return employeeRepository.findAll();
    }

    public Page<Employee> getEmployeesWithPagination(int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size);
        return employeeRepository.findAll(pageRequest);
    }

    public Optional<Employee> getEmployeeById(Long id) {
        return employeeRepository.findById(id);
    }

    public Employee getEmployeeByEmail(String email) {
        return employeeRepository.findByEmail(email);
    }
    public Employee getEmployeeByPhone(String phone) {
        Employee employee = employeeRepository.findByPhone(phone);
        return employee != null ? employee : null;
    }

    public List<Long> findEmployeeIdsByPosition(String position) {
        return employeeRepository.findEmployeeIdsByPosition(position);
    }

    public Employee saveEmployee(Employee employee, MultipartFile file) throws IOException {
        String imageUrl = storageService.uploadImage(file);
        employee.setImage(imageUrl);
        //mã hoá mật khâủ
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);
        employee.setPassword(passwordEncoder.encode(employee.getPassword()));

        return employeeRepository.save(employee);
    }

    public Employee saveEmployee(Employee employee)  {
        //mã hoá mật khâủ
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);
        employee.setPassword(passwordEncoder.encode(employee.getPassword()));
        return employeeRepository.save(employee);
    }

    public void updateEmployee(Long id, Employee updatedEmployee, MultipartFile file) throws IOException {
        Employee existingEmployee = employeeRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Employee not found with id: " + updatedEmployee.getId()));

        existingEmployee.setId(id);
        existingEmployee.setName(updatedEmployee.getName());
        existingEmployee.setPosition(updatedEmployee.getPosition());
        existingEmployee.setPhone(updatedEmployee.getPhone());
        existingEmployee.setEmail(updatedEmployee.getEmail());

        if (file != null && !file.isEmpty()) {
            existingEmployee.setImage(storageService.uploadImage(file));
        }

        employeeRepository.save(existingEmployee);
    }


    public void deleteEmployee(Long id) {
        employeeRepository.deleteById(id);
    }
}
