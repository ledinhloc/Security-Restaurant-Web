package com.restaurant.management.service;
import com.restaurant.management.model.Discount;
import com.restaurant.management.repository.DiscountRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class DiscountService {
    @Autowired
    private final DiscountRepository discountRepository;

    public List<Discount> getAllDiscounts() {
        return discountRepository.findAll();
    }

    public Discount getDiscountById(Long id) {
        return discountRepository.findById(id).orElseThrow(()-> new RuntimeException("Discount not found"));
    }

    public Optional<Discount> getDiscountByCode(String code) {
        return discountRepository.findByCode(code);
    }

    public Discount saveDiscount(Discount discount) {
        return discountRepository.save(discount);
    }

    public void deleteDiscount(Long id) {
        discountRepository.deleteById(id);
    }

    @Transactional
    public double applyDiscount(String code, Double orderAmount) {
        Optional<Discount> optionalDiscount = discountRepository.findByCode(code);
        if (optionalDiscount.isPresent()) {
            Discount discount = optionalDiscount.get();
            if (discount.getIsActive() && discount.getTimesUsed() < discount.getUsageLimit() &&
                    discount.getEndDate().isAfter(LocalDate.now())) {
                discount.setTimesUsed(discount.getTimesUsed() + 1);
                discountRepository.save(discount);

                return orderAmount * ((double)discount.getPercentage() / 100);
            }
        }

        return 0;
    }

}