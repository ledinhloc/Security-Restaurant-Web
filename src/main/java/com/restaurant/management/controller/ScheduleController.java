package com.restaurant.management.controller;

import com.restaurant.management.model.Employee;
import com.restaurant.management.model.Schedule;
import com.restaurant.management.service.EmployeeService;
import com.restaurant.management.service.ScheduleService;
import com.restaurant.management.service.SchedulingSolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/schedules")
public class ScheduleController {
    @Autowired
    private ScheduleService scheduleService;
    @Autowired
    private EmployeeService employeeService;

    @GetMapping("/list")
    public ResponseEntity<Map<String, List<Schedule>>> getSchedules(
            @RequestParam("startDate") LocalDate startDate,
            @RequestParam("endDate") LocalDate endDate
    ) {
        Map<String, List<Schedule>> schedules = scheduleService.getSchedulesByDateRange(startDate, endDate);
        return ResponseEntity.ok(schedules);
    }

    @GetMapping("")
    public String viewSchedules(Model model) {
        return "pages/schedule/view-schedule";
    }

    @PostMapping
    public ResponseEntity<Schedule> createSchedule(@RequestBody Schedule schedule,
                                                   @RequestParam(required = false) Long shiftId,
                                                   @RequestParam Long employeeId) {
        System.out.println(shiftId);
        Schedule createdSchedule = scheduleService.createSchedule(schedule, shiftId, employeeId);
        return new ResponseEntity<>(createdSchedule, HttpStatus.CREATED);
    }

    @DeleteMapping("/{scheduleId}")
    public ResponseEntity<Void> deleteSchedule(@PathVariable Long scheduleId) {
        scheduleService.deleteSchedule(scheduleId);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{scheduleId}")
    public ResponseEntity<Schedule> getScheduleById(@PathVariable Long scheduleId) {
        return scheduleService.getScheduleById(scheduleId)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/{scheduleId}")
    public ResponseEntity<Schedule> updateSchedule(
            @PathVariable Long scheduleId,
            @RequestBody Map<String, Object> updates) {

        LocalDate workingDate = LocalDate.parse((String) updates.get("workingDate"));
        Long employeeId = Long.valueOf(updates.get("employeeId").toString());
        Schedule updatedSchedule = scheduleService.updateSchedule(scheduleId, workingDate, employeeId);

        return ResponseEntity.ok(updatedSchedule);
    }
    @GetMapping("/config")
    public String sendMatrix(Model model) {
        return "pages/schedule/auto-scheduling-conf";
    }

    @PostMapping("/config")
    public ResponseEntity<?> submitMatrix(@RequestBody Map<String, Object> requestBody) {
        String startDate = (String) requestBody.get("startDate");
        int maxShiftPerDay = Integer.parseInt(requestBody.get("maxShiftPerDay").toString());
        int maxDeviationShift = Integer.parseInt(requestBody.get("maxDeviationShift").toString());
        int isConsecutiveShifts = Integer.parseInt(requestBody.get("isConsecutiveShifts").toString());

        List<List<Integer>> staffMatrix = (List<List<Integer>>) requestBody.get("staffMatrix");
        List<List<Integer>> chefMatrix = (List<List<Integer>>) requestBody.get("chefMatrix");
        scheduleService.autoSchedulingShitf(startDate, "STAFF", staffMatrix, maxShiftPerDay, maxDeviationShift, isConsecutiveShifts);
        scheduleService.autoSchedulingShitf(startDate, "CHEF", chefMatrix, maxShiftPerDay, maxDeviationShift, isConsecutiveShifts);
        return ResponseEntity.ok("success");
    }

    @PostMapping("/completed")
    public ResponseEntity<Void> markAsCompletedSchedule(@RequestBody Map<String, Long> requestBody) {
        Long scheduleId = requestBody.get("scheduleId");
        scheduleService.updateScheduleStatus(scheduleId, "COMPLETED");
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/published")
    public ResponseEntity<String> publishAllSchedules() {
        scheduleService.publishAllSchedules();
        return ResponseEntity.ok("All schedules have been published successfully");
    }

    @GetMapping("/employee-schedule")
    public String getEmployeeSchedule(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate,
            Model model
    ) {
        // If no dates provided, default to current month
        if (startDate == null || endDate == null) {
            LocalDate now = LocalDate.now();
            startDate = now.withDayOfMonth(1);
            endDate = now.withDayOfMonth(now.lengthOfMonth());
        }

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String customerEmail = ((UserDetails) principal).getUsername();
        Employee employee = employeeService.getEmployeeByEmail(customerEmail);

        List<Schedule> schedules = scheduleService.findSchedulesByEmployeeAndDateRange(
                employee.getId(), startDate, endDate
        );

        model.addAttribute("employee", employee);
        model.addAttribute("schedules", schedules);
        model.addAttribute("startDate", startDate);
        model.addAttribute("endDate", endDate);

        return "pages/schedule/employee-schedule";
    }
}
