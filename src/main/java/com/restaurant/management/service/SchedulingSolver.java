package com.restaurant.management.service;

import com.google.ortools.Loader;
import com.google.ortools.sat.*;
import com.restaurant.management.util.MatrixUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

public class SchedulingSolver {
    public int[][][] solveConstraint(
            int numEmp,
            int numShifts,
            int numDays,
            int[][] numEmpPerShift,
            int maxShiftPerDay,
            int maxDeviationShifts,
            int consecutiveShifts
    ) {
        // Load OR-Tools native libraries
        Loader.loadNativeLibraries();

        // Generate default num_emp_per_shift if null
        if (numEmpPerShift == null) {
            numEmpPerShift = MatrixUtil.generateRandomNumEmp(numDays, numShifts);
        }
        numEmpPerShift = MatrixUtil.transpose(numEmpPerShift);

        int[] allEmp = IntStream.range(0, numEmp).toArray();
        int[] allShifts = IntStream.range(0, numShifts).toArray();
        int[] allDays = IntStream.range(0, numDays).toArray();

        // Calculate shift counts and totals
        int[] shiftCount = MatrixUtil.sumColumns(numEmpPerShift);
        int sumShifts = MatrixUtil.sumOfMatrix(numEmpPerShift);

        // Create the model
        CpModel model = new CpModel();

        // Create shift variables
        Literal[][][] shifts = new Literal[numEmp][numDays][numShifts];
        for (int n = 0; n < numEmp; n++) {
            for (int d = 0; d < numDays; d++) {
                for (int s = 0; s < numShifts; s++) {
                    shifts[n][d][s] = model.newBoolVar("shift_n" + n + "_d" + d + "_s" + s);
                }
            }
        }

        // DEFAULT CONSTRAINT 1: Each shift is assigned to exactly number of emp in numEmpPerShift array
        for (int d = 0; d < numDays; d++) {
            for (int s = 0; s < numShifts; s++) {
                List<Literal> shiftAssignments = new ArrayList<>();
                for (int emp = 0; emp < numEmp; emp++) {
                    shiftAssignments.add(shifts[emp][d][s]);
                }
                model.addEquality(LinearExpr.sum(shiftAssignments.toArray(new Literal[0])), numEmpPerShift[d][s]);
            }
        }

        // DEFAULT CONSTRAINT 2: Distribute shifts evenly
        int minShiftsPerEmp = sumShifts / numEmp;
        int maxShiftsPerEmp = (sumShifts % numEmp == 0) ? minShiftsPerEmp : minShiftsPerEmp + 1;
        for (int n : allEmp) {
            List<Literal> shiftsWorked = new ArrayList<>();
            for (int d : allDays) {
                for (int s : allShifts) {
                    shiftsWorked.add(shifts[n][d][s]);
                }
            }
            model.addGreaterOrEqual(LinearExpr.sum(shiftsWorked.toArray(new Literal[0])), minShiftsPerEmp);
            model.addLessOrEqual(LinearExpr.sum(shiftsWorked.toArray(new Literal[0])), maxShiftsPerEmp);
        }

        // DEFAULT CONSTRAINT 3: Equal number of shifts per shift type with max deviation
        for (int shift = 0; shift < numShifts; shift++) {
            for (int emp : allEmp) {
                List<Literal> shiftsWorked = new ArrayList<>();
                for (int day : allDays) {
                    shiftsWorked.add(shifts[emp][day][shift]);
                }
                int target = shiftCount[shift] / numEmp;
                model.addLinearConstraint(
                        LinearExpr.sum(shiftsWorked.toArray(new Literal[0])),
                        target - maxDeviationShifts,
                        target + maxDeviationShifts
                );
            }
        }

        // DEFAULT CONSTRAINT 4: Max shifts per day
        for (int n : allEmp) {
            for (int d : allDays) {
                List<Literal> dayShifts = new ArrayList<>();
                for (int s : allShifts) {
                    dayShifts.add(shifts[n][d][s]);
                }
                model.addLessOrEqual(LinearExpr.sum(dayShifts.toArray(new Literal[0])), maxShiftPerDay);
            }
        }

        // OPTIONAL CONSTRAINT 1: Not working consecutive shifts
        if (consecutiveShifts != 0) {
            for (int nurse : allEmp) {
                for (int day : allDays) {
                    for (int shift = 0; shift < numShifts - 1; shift++) {
                        model.addLessOrEqual(
                                LinearExpr.sum(new Literal[]{shifts[nurse][day][shift], shifts[nurse][day][shift + 1]}),
                                1
                        );
                    }
                }
            }
        }

        CpSolver solver = new CpSolver();
        CpSolverStatus status = solver.solve(model);
        int[][][] solution = new int[numEmp][numDays][numShifts];

        if (status == CpSolverStatus.OPTIMAL || status == CpSolverStatus.FEASIBLE) {
            System.out.println("Optimal solution found: " + status);
            for (int i = 0; i < shifts.length; i++) {
                for (int j = 0; j < shifts[i].length; j++) {
                    for (int k = 0; k < shifts[i][j].length; k++) {
                        solution[i][j][k] = solver.booleanValue(shifts[i][j][k]) ? 1 : 0;
                    }
                }
            }
        } else {
            System.out.println("Status:: " +  status);
        }
        return solution;
    }


}
