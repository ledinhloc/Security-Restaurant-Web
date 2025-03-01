package com.restaurant.management.service;

import com.restaurant.management.enums.ShiftType;
import com.restaurant.management.model.Employee;
import com.restaurant.management.model.Schedule;
import com.restaurant.management.model.Shift;
import com.restaurant.management.repository.ScheduleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
@Service
public class ScheduleService {
    @Autowired
    private ScheduleRepository scheduleRepository;
    @Autowired
    private EmployeeService employeeService;
    @Autowired
    private ShiftService shiftService;

    public Map<String,List<Schedule>> getSchedulesByDateRange(LocalDate startDate, LocalDate endDate) {
        List<Schedule> schedules = scheduleRepository.findByWorkingDateBetween(startDate, endDate);

        return schedules.stream().collect(
                Collectors.groupingBy(
                    schedule -> schedule.getWorkingDate().toString()
                )
        );
    }

    public Schedule createSchedule(Schedule schedule, Long shiftId, Long employeeId) {
        if (shiftId != null) {
            Shift shift = shiftService.getShift(shiftId);
            schedule.setShift(shift);
        }

        Optional<Employee> employee = employeeService.getEmployeeById(employeeId);
        if (employee.isPresent()) {
            schedule.setEmployee(employee.get());
        }

        return scheduleRepository.save(schedule);  // Lưu Schedule vào DB
    }

    public void createSchedulesForFixedShift(Shift shift) {
        LocalDate startDate = LocalDate.now();
        LocalDate endDate = startDate.plusMonths(1);

        for (LocalDate date = startDate; !date.isAfter(endDate); date = date.plusDays(1)) {
            Schedule schedule = Schedule.builder()
                    .shift(shift)
                    .employee(shift.getEmployee())
                    .startTime(shift.getStartTime())
                    .endTime(shift.getEndTime())
                    .workingDate(date)
                    .status("DRAFT")
                    .build();

            scheduleRepository.save(schedule);
        }
    }

    public void deleteSchedule(Long scheduleId) {
        if (scheduleRepository.existsById(scheduleId)) {
            scheduleRepository.deleteById(scheduleId);
        } else {
            throw new IllegalArgumentException("Schedule not found with id: " + scheduleId);
        }
    }

    public Optional<Schedule> getScheduleById(Long scheduleId) {
        return scheduleRepository.findById(scheduleId);
    }

    public void updateScheduleStatus(Long scheduleId, String status) {
        Schedule schedule = scheduleRepository.findById(scheduleId)
                .orElseThrow(() -> new RuntimeException("Schedule not found with id: " + scheduleId));

        schedule.setStatus(status);
        scheduleRepository.save(schedule);
    }

    public Schedule updateSchedule(Long scheduleId, LocalDate workingDate, Long employeeId) {
        Schedule schedule = scheduleRepository.findById(scheduleId)
                .orElseThrow(() -> new IllegalArgumentException("Schedule not found with id: " + scheduleId));

        schedule.setWorkingDate(workingDate);

        if (employeeId != null) {
            Employee employee = employeeService.getEmployeeById(employeeId)
                    .orElseThrow(() -> new IllegalArgumentException("Employee not found with id: " + employeeId));
            schedule.setEmployee(employee);
        }

        return scheduleRepository.save(schedule);
    }

    public Schedule registerEmployeeToShift(Long employeeId, Long shiftId) {
        Shift shift = shiftService.registerForShift(shiftId);
        Optional<Employee> employee = employeeService.getEmployeeById(employeeId);
        Schedule schedule = Schedule.builder()
                .employee(employee.get())
                .shift(shift)
                .startTime(shift.getStartTime())
                .endTime(shift.getEndTime())
                .status("PUBLISHED")
                .workingDate(shift.getWorkingDate())
                .build();

        return scheduleRepository.save(schedule);
    }

    public void cancelRegistration(Long scheduleId) {
        Schedule schedule = scheduleRepository.findById(scheduleId)
                .orElseThrow(() -> new IllegalArgumentException("Schedule not found."));
        shiftService.cancelShiftRegistration(schedule.getShift().getShiftId());
        scheduleRepository.delete(schedule);
    }

    public void saveSchedule(int[][][] solution, LocalDate startDate, LocalDate endDate, String position) {
        List<Long> employeeIds = employeeService.findEmployeeIdsByPosition(position);
        List<Long> shiftIds = shiftService.getRegularShiftIds(ShiftType.REGULAR);

        for (int emp = 0; emp < solution.length; emp++) {
            for (int day = 0; day < solution[emp].length; day++) {
                for (int shift = 0; shift < solution[emp][day].length; shift++) {
                    if (solution[emp][day][shift] == 1) {
                        Shift shiftEntity = shiftService.getShift(shiftIds.get(shift));
                        Schedule schedule = Schedule.builder()
                                .employee(employeeService.getEmployeeById(employeeIds.get(emp)).get())
                                .shift(shiftEntity)
                                .startTime(shiftEntity.getStartTime())
                                .endTime(shiftEntity.getEndTime())
                                .workingDate(startDate.plusDays(day))
                                .status("DRAFF")
                                .build();

                        scheduleRepository.save(schedule);
                    }
                }
            }
        }
    }

    public void autoSchedulingShitf(String startDate, String role, List<List<Integer>> numEmpPerShift, int maxShiftPerDay,
                                    int maxDeviationShift, int isConsecutiveShifts) {
        // Xử lý ma trận staff và chef chuyển đổi từ List<List<Integer>> thành mảng 2D int[])
        int[][] staffMatrixArray = new int[numEmpPerShift.size()][];
        for (int i = 0; i < numEmpPerShift.size(); i++) {
            staffMatrixArray[i] = numEmpPerShift.get(i).stream().mapToInt(Integer::intValue).toArray();
        }
        int numRegularShift = shiftService.getRegularShifts().size();
        int numEmployee = employeeService.findEmployeeIdsByPosition(role).size();
        SchedulingSolver solver = new SchedulingSolver();
        int[][][] solution = solver.solveConstraint(numEmployee, numRegularShift, 7,
                staffMatrixArray, maxShiftPerDay, maxDeviationShift, isConsecutiveShifts);

        saveSchedule(solution, LocalDate.parse(startDate), LocalDate.parse(startDate).plusDays(7), role);
    }

    public void publishAllSchedules() {
        List<Schedule> schedules = scheduleRepository.findAll();

        schedules.forEach(schedule -> {
            schedule.setStatus("PUBLISHED");
        });

        scheduleRepository.saveAll(schedules);
    }

    public List<Schedule> findSchedulesByEmployeeAndDateRange(Long employeeId, LocalDate startDate, LocalDate endDate) {
        return scheduleRepository.findByEmployeeIdAndWorkingDateBetweenAndStatus(
                employeeId,
                startDate,
                endDate,
                "PUBLISHED"
        );
    }
}
