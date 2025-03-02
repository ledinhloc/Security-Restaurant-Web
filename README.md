# Hướng dẫn Cài đặt và Sử Dụng Dự Án

## 📌 Tổng quan
- **Ngôn ngữ:** Java 17+
- **Framework:** Spring Boot 3
- **Cơ sở dữ liệu:** MySQL
- **ORM:** JPA (Jakarta Persistence API)
- **Front-end:** Thymeleaf, TailwindCSS
- **Tích hợp dịch vụ bên thứ ba:**
    - 🌩 **Cloudinary** (lưu trữ hình ảnh)
    - 💳 **VNPay** (thanh toán trực tuyến)
    - 📩 **Twilio** (gửi tin nhắn SMS)
- **Mô hình kiến trúc:** MVC (Model - View - Controller)
- **IDE:** IntelliJ IDEA

---

## 🛠 Yêu cầu hệ thống
- **JDK 17+** → [Tải tại đây](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html)
- **IntelliJ IDEA** → [Tải tại đây](https://www.jetbrains.com/idea/download/)
- **Apache Maven 3.9+** → [Tải tại đây](https://maven.apache.org/download.cgi)
- **MySQL Server** → [Tải tại đây](https://dev.mysql.com/downloads/installer/)

---

## 🚀 Các bước cài đặt
### 1️⃣ Clone dự án
```sh
git clone https://github.com/ledinhloc/Security-Restaurant-Web
```

### 2️⃣ Cấu hình database
- Thiết lập **MySQL Database** và tạo một database mới . 
```mysql
  CREATE DATABASE restaurant;
```
- Chạy file data_db.sql để khởi tạo dữ liệu ban đầu.

### 3️⃣ Cấu hình biến môi trường
Ở file cấu hình `src/main/resources/application.yaml`
#### Cách sử dụng file `.env`
Tạo file `.env` với nội dung dưới và sửa các biến môi trường.
Thêm thông tin cấu hình cho **Cloudinary**, **VNPay**, **Twilio** vào file này.

```env
DB_URL=jdbc:mysql://localhost:3306/restaurant
DB_USERNAME=root
DB_PASSWORD=1234567890

CLOUDINARY_NAME=your_cloud_name
CLOUDINARY_KEY=your_api_key
CLOUDINARY_SECRET=your_api_secret

VNP_TMNCODE=your_tmncode
VNP_SECRETKEY=your_secret_key
VNP_RETURNURL=http://localhost:8080/payment/vn-pay-callback

TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE_NUMBER=your_phone_number
```

####  Cài đặt Plugin Hỗ Trợ `.env`
Để sử dụng file `.env`, cần cài đặt plugin hỗ trợ trên IntelliJ IDEA:

1. Vào **File** → **Settings** (`Ctrl + Alt + S`).
2. Chọn **Plugins**.
3. Tìm kiếm **"Env File Support"**.
4. Nhấn **Install** và khởi động lại IntelliJ IDEA.

####  Thêm File .env vào IntelliJ IDEA
Để sử dụng file `.env`, cần cài đặt plugin hỗ trợ trên IntelliJ IDEA:

1. Vào Run → Edit Configurations....
2. Tích chọn Enable EnvFile
3. Chọn add và chọn file .env đã tạo

### 4️⃣ Cài đặt và chạy dự án
```sh
mvn clean install
mvn spring-boot:run
```

### 5️⃣ Truy cập ứng dụng
Mở trình duyệt và truy cập: [`http://localhost:8080`](http://localhost:8080)

---

## 📌 Lưu ý
✅ Hình ảnh tải lên được lưu trên **Cloudinary**.
✅ Hướng dẫn thanh toán qua VNPay:
---

## 📚 Tài liệu tham khảo

---
✨ Chúc bạn cài đặt và sử dụng dự án thành công! 🚀

