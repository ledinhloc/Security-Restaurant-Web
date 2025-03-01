package com.restaurant.management.service;

import com.restaurant.management.enums.SalaryStatus;
import com.restaurant.management.model.Employee;
import com.restaurant.management.model.Salary;
import com.restaurant.management.model.Schedule;
import com.restaurant.management.repository.EmployeeRepository;
import com.restaurant.management.repository.SalaryRepository;
import com.restaurant.management.repository.ScheduleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDate;
import java.util.List;

@Service
public class SalaryService {
    @Autowired
    private SalaryRepository salaryRepository;
    @Autowired
    private ScheduleRepository scheduleRepository;
    @Autowired
    private EmployeeRepository employeeRepository;

    public List<Salary> getsalaryByPayDate(LocalDate start, LocalDate end) {
        return salaryRepository.findByPayDateBetween(start, end);
    }

    public void calculatesalary(LocalDate startDate, LocalDate endDate) {
        List<Employee> employees = employeeRepository.findAll();

        for (Employee employee : employees) {
            List<Schedule> schedules = scheduleRepository.findByEmployeeIdAndWorkingDateBetween(employee.getId(), startDate, endDate);

            double totalHours = schedules.stream()
                    .filter(schedule -> schedule.getStatus().equals("COMPLETED"))
                    .mapToDouble(schedule -> {
                        long hoursWorked = Duration.between(schedule.getStartTime(), schedule.getEndTime()).toHours();
                        return hoursWorked;
                    })
                    .sum();

            double hourlyRate = 20000;

            double totalSalary = totalHours * hourlyRate;

            Salary salary = salaryRepository.findByEmployeeIdAndPayDateBetween(employee.getId(), startDate, endDate);

            if (salary == null) {
                salary = Salary.builder()
                        .employee(employee)
                        .payDate(endDate)
                        .totalHoursWorked(totalHours)
                        .hourlyRate(hourlyRate)
                        .totalSalary(totalSalary)
                        .status(SalaryStatus.PENDING)
                        .bonus(0D)
                        .build();
            } else {
                salary.setTotalHoursWorked(totalHours);
                salary.setTotalSalary(salary.getTotalHoursWorked()*salary.getHourlyRate() + salary.getBonus());
            }
            salaryRepository.save(salary);
        }
    }

    public void updateSalary(Long id, Double hourlyRate, Double bonus) {
        Salary salary = salaryRepository.findById(id).orElseThrow(() -> new RuntimeException("Salary not found"));
        salary.setHourlyRate(hourlyRate);
        salary.setBonus(bonus);
        salary.setTotalSalary(salary.getTotalHoursWorked()*salary.getHourlyRate() + bonus);
        salaryRepository.save(salary);
    }


    public void payAllsalary() {
        List<Salary> salaries = salaryRepository.findAll();
        for (Salary salary : salaries) {
            if (salary.getStatus() != SalaryStatus.PAID) {
                salary.setStatus(SalaryStatus.PAID);
                salaryRepository.save(salary);
            }
        }
    }

}