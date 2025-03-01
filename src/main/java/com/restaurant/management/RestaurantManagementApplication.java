package com.restaurant.management;

import com.restaurant.management.service.SchedulingSolver;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
@EnableScheduling
public class RestaurantManagementApplication {

	public static void main(String[] args) {
		SpringApplication.run(RestaurantManagementApplication.class, args);

		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

		// Mã hóa mật khẩu
		String rawPassword = "123"; // Mật khẩu gốc
		String encodedPassword = encoder.encode(rawPassword); // Mật khẩu đã mã hóa

		System.out.println("Encoded Password: " + encodedPassword);
//		SchedulingSolver solver = new SchedulingSolver();
	}

}
