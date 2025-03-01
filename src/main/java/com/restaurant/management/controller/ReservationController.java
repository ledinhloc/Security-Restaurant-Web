package com.restaurant.management.controller;

import com.restaurant.management.model.Reservation;
import com.restaurant.management.service.ReservationService;
import com.restaurant.management.service.TableService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;

@Controller
@RequestMapping("/reservations")
public class ReservationController {

    @Autowired
    private ReservationService reservationService;
    @Autowired
    private TableService tableService;

    @GetMapping("")
    @PreAuthorize("hasRole('ADMIN')")
    public String listReservations(
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String dateFilter,
            @RequestParam(required = false) String status,
            Model model
    ) {
        List<Reservation> filteredReservations = reservationService.findWithFilters(search, dateFilter, status);
        model.addAttribute("reservations", filteredReservations);
        model.addAttribute("pendingReser", reservationService.countPendingReservations());
        model.addAttribute("todayReser", reservationService.countTodayReservations());
        model.addAttribute("confirmedReser", reservationService.countConfirmedReservations());
        return "pages/reservation/view-list";
    }

    @GetMapping("/booking")
    @PreAuthorize("hasRole('ADMIN') AND hasRole('CUSTOMER')")
    public String booking(Model model,
           @RequestParam(value = "dateToCome", required = false) LocalDate reserDate,
           @RequestParam(value = "timeToCome", required = false) LocalTime reserTime,
           @RequestParam(value = "people", required = false) Long numPeople) {
        if (reserDate != null && reserTime != null) {
            model.addAttribute("tables", reservationService.findAvailable(reserDate, reserTime, numPeople));
            model.addAttribute("reservation", Reservation.builder()
                    .dateToCome(reserDate)
                    .timeToCome(reserTime)
                    .build());

            return "pages/reservation/form";
        } else return "pages/reservation/booking";
    }

    @PostMapping("/create")
    public String createReservation(@ModelAttribute Reservation reservation) {
        System.out.println(reservation);
        reservationService.save(reservation);
        return "redirect:/profile";
    }

    @GetMapping("/edit/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String showEditForm(@PathVariable Long id, Model model) {
        Reservation reservation = reservationService.findById(id);
        model.addAttribute("tables", tableService.getAllTables());
        model.addAttribute("reservation", reservation);
        return "pages/reservation/form";
    }

    @GetMapping("/accept/{tableId}")
    @PreAuthorize("hasRole('ADMIN')")
    public String acceptReservation(@PathVariable Long tableId) {
        reservationService.acceptReservation(tableId);
        return "redirect:/reservations";
    }

    @GetMapping("/cancel/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String deleteReservation(@PathVariable Long id) {
        reservationService.cancelReservation(id);
        return "redirect:/reservations";
    }
}