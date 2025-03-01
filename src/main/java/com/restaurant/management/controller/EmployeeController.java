package com.restaurant.management.controller;

import com.restaurant.management.model.Employee;
import com.restaurant.management.service.EmployeeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Controller
@RequestMapping("/employees")
public class EmployeeController {
    @Autowired
    private EmployeeService employeeService;

//    @GetMapping
//    public String listEmployees(Model model) {
//        model.addAttribute("employees", employeeService.getAllEmployees());
//        return "pages/employee/list";
//    }

    @GetMapping
    public String listEmployees(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "5") int size,
            Model model) {

        Page<Employee> employeePage = employeeService.getEmployeesWithPagination(page, size);
        model.addAttribute("employees", employeePage.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", employeePage.getTotalPages());
        return "pages/employee/list";
    }


    @GetMapping("/list")
    public ResponseEntity<List<Employee>> listEmployees() {
        List<Employee> employees = employeeService.getAllEmployees();
        return ResponseEntity.ok(employees);
    }

    @PostMapping("/add")
    public String addEmployee(@ModelAttribute Employee employee,
                              @RequestParam("file") MultipartFile file) {
        try {
            employeeService.saveEmployee(employee, file);
            return "redirect:/employees";
        }
        catch (Exception e) {
            return "redirect:/employees";
        }
    }

    @PostMapping("/edit/{id}")
    public String updateEmployee(@PathVariable Long id,
                                 @ModelAttribute Employee employee,
                                 @RequestParam("file") MultipartFile file) {
        try {
            employeeService.updateEmployee(id, employee, file);
            return "redirect:/employees";
        } catch (Exception e) {
            e.printStackTrace();
            return "error";
        }
    }


    @GetMapping("/delete/{id}")
    public String deleteEmployee(@PathVariable Long id) {
        employeeService.deleteEmployee(id);
        return "redirect:/employees";
    }
}
