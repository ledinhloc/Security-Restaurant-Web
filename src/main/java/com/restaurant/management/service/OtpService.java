package com.restaurant.management.service;

import com.restaurant.management.model.Otp;
import com.restaurant.management.repository.OtpRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class OtpService {
    @Autowired
    private OtpRepository otpRepository;

    public Otp save(Otp otp) {
        return otpRepository.save(otp);
    }

    public Otp findOtp(String phoneNumber, String otpCode) {
        return otpRepository.findByPhoneNumberAndOtpCodeAndIsUsedFalse(phoneNumber, otpCode);
    }

    // Cập nhật OTP là đã sử dụng
    public void markOtpAsUsed(Otp otp) {
        otp.setUsed(true);
        otpRepository.save(otp);
    }
}
