package com.restaurant.management.repository;

import com.restaurant.management.model.Otp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OtpRepository extends JpaRepository<Otp, Long> {
    Otp findByPhoneNumberAndOtpCodeAndIsUsedFalse(String phoneNumber, String otpCode);
}
