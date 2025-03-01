package com.restaurant.management.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.sql.SQLException;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(value = Exception.class)
    public String handleException(Exception ex, Model model) {
        model.addAttribute("errorMessage", ex.getMessage());
        return "pages/error";
    }

    @ExceptionHandler(value = DataIntegrityViolationException.class)
    public String handleSQLException(Exception ex, Model model) {
        // Kiểm tra nếu lỗi là vi phạm khóa ngoại (foreign key constraint violation)
        if (ex.getMessage().contains("FOREIGN KEY")) {
            model.addAttribute("errorMessage", "Cannot delete this record because it is referenced by other records. Please remove references first.");
        } else {
            model.addAttribute("errorMessage", "An unexpected error occurred: " + ex.getMessage());
        }
        return "pages/error";
    }


}
