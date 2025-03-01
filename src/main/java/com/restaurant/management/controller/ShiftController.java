package com.restaurant.management.controller;

import com.restaurant.management.model.Shift;
import com.restaurant.management.service.EmployeeService;
import com.restaurant.management.service.ScheduleService;
import com.restaurant.management.service.ShiftService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.time.LocalDate;
import java.util.List;

@Controller
@RequestMapping("/shifts")
public class ShiftController {
    @Autowired
    private ScheduleService scheduleService;
    @Autowired
    private ShiftService shiftService;
    @Autowired
    private EmployeeService employeeService;

    @GetMapping
    private String showShiftList(Model model) {
        model.addAttribute("shiftList", shiftService.getRegularShifts());
        model.addAttribute("openShifts", shiftService.getOpenShifts());
        model.addAttribute("fixedShifts", shiftService.getFixedShifts());
        model.addAttribute("employees", employeeService.getAllEmployees());
        model.addAttribute("shift", new Shift());
        return "pages/schedule/shift-list";
    }

    @GetMapping("edit/{shiftId}")
    private String showShiftList(Model model, @PathVariable Long shiftId) {
        model.addAttribute("shiftList", shiftService.getRegularShifts());
        model.addAttribute("openShifts", shiftService.getOpenShifts());
        model.addAttribute("fixedShifts", shiftService.getFixedShifts());
        model.addAttribute("employees", employeeService.getAllEmployees());
        model.addAttribute("shift", shiftService.getShift(shiftId));
        model.addAttribute("modalStatus", "open");
        return "pages/schedule/shift-list";
    }

    @PostMapping
    private String createShift(Model model, @ModelAttribute Shift shift) {
        System.out.println(shift);
        shiftService.createShift(shift);
        model.addAttribute("employees", employeeService.getAllEmployees());
        model.addAttribute("shiftList", shiftService.getRegularShifts());
        model.addAttribute("openShifts", shiftService.getOpenShifts());
        model.addAttribute("fixedShifts", shiftService.getFixedShifts());
        model.addAttribute("shift", new Shift());

        return "pages/schedule/shift-list";
    }

    @GetMapping("/available")
    public String getAvailableShifts(Model model) {
        model.addAttribute("availbleShifts", shiftService.getAvailableShifts());
        return "pages/schedule/shift-register";
    }

    @GetMapping("/delete/{id}")
    public String deleteReservation(@PathVariable Long id) {
        shiftService.deleteShift(id);
        return "redirect:/shifts";
    }

    @GetMapping("/list")
    @ResponseBody
    public List<Shift> getListRegularShift() {
        return shiftService.getRegularShifts();
    }

    @GetMapping("/register")
    public String registerShitf(Model model) {
        model.addAttribute("availbleShifts", shiftService.getAvailableShifts());
        return "pages/schedule/shift-register";
    }

    @PostMapping("/register/{shiftId}")
    public String registerForShift(@PathVariable Long shiftId, Principal principal) {
        String username = principal.getName();
        Long employeeId = employeeService.getEmployeeByEmail(username).getId();
        scheduleService.registerEmployeeToShift(employeeId, shiftId);
        return "redirect:/profile";
    }

    @PostMapping("/cancel/{scheduleId}")
    public String cancelShift(@PathVariable Long scheduleId) {
        scheduleService.cancelRegistration(scheduleId);

        return "redirect:/shifts/register";
    }
}
