package com.restaurant.management.util;

import lombok.experimental.UtilityClass;

@UtilityClass
public class MatrixUtil {
    public static int[][] generateRandomNumEmp(int numDays, int numShifts) {
        int[][] result = new int[numDays][numShifts];
        for (int i = 0; i < numDays; i++) {
            for (int j = 0; j < numShifts; j++) {
                result[i][j] = 2;
            }
        }
        return result;
    }

    public static int[] sumColumns(int[][] matrix) {
        int[] columnSums = new int[matrix[0].length];
        for (int j = 0; j < matrix[0].length; j++) {
            for (int[] row : matrix) {
                columnSums[j] += row[j];
            }
        }
        return columnSums;
    }

    public static int sumOfMatrix(int[][] matrix) {
        int sum = 0;
        for (int[] row : matrix) {
            for (int val : row) {
                sum += val;
            }
        }
        return sum;
    }

    public static int[][] transpose(int[][] matrix) {
        int rows = matrix.length;
        int cols = matrix[0].length;
        int[][] transposedMatrix = new int[cols][rows];
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                transposedMatrix[j][i] = matrix[i][j];
            }
        }

        return transposedMatrix;
    }

    public void print3DMatrix(int[][][] matrix) {
        for (int i = 0; i < matrix.length; i++) {
            System.out.println("Mảng thứ " + (i + 1) + ":");
            for (int j = 0; j < matrix[i].length; j++) {
                for (int k = 0; k < matrix[i][j].length; k++) {
                    System.out.print(matrix[i][j][k] + " ");
                }
                System.out.println();
            }
            System.out.println();
        }
    }
}
