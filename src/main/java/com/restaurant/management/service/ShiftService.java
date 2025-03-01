package com.restaurant.management.service;

import com.restaurant.management.enums.ShiftType;
import com.restaurant.management.model.Shift;
import com.restaurant.management.repository.ShiftRepository;
import jdk.jfr.Label;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@Service
public class ShiftService {
    @Autowired
    private ShiftRepository shiftRepository;
    @Autowired
    @Lazy
    private ScheduleService scheduleService;

    public List<Shift> getRegularShifts() {
        return shiftRepository.findByShiftType(ShiftType.REGULAR);
    }

    public List<Shift> getOpenShifts() {
        return shiftRepository.findByShiftType(ShiftType.OPEN);
    }

    public List<Shift> getFixedShifts() {
        return shiftRepository.findByShiftType(ShiftType.FIXED);
    }

    public Shift createShift(Shift shift) {
        Shift savedShift = shiftRepository.save(shift);
        if (shift.getShiftType() == ShiftType.FIXED && shift.getEmployee() != null) {
            scheduleService.createSchedulesForFixedShift(savedShift);
        }
        return savedShift;
    }

    public Shift getShift(Long id) {
        return shiftRepository.findById(id).orElseThrow(() -> new RuntimeException("Shift not found for ID: " + id));
    }

    public List<Long> getRegularShiftIds(ShiftType type) {
        return shiftRepository.findShiftIdsByShiftType(type);
    }

    public List<Shift> getAvailableShifts() {
        return shiftRepository.findAvailableShifts();
    }

    public Shift registerForShift(Long shiftId) {
        Shift shift = shiftRepository.findById(shiftId)
                .orElseThrow(() -> new IllegalArgumentException("Shift not found."));
        shift.registerShift();
        return shiftRepository.save(shift);
    }

    public void cancelShiftRegistration(Long shiftId) {
        Shift shift = shiftRepository.findById(shiftId)
                .orElseThrow(() -> new IllegalArgumentException("Shift not found."));
        shift.cancelRegistration();
        shiftRepository.save(shift);
    }

    public void deleteShift(Long id) {
        shiftRepository.deleteById(id);
    }
}
