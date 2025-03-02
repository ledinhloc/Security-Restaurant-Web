-- MySQL dump 10.13  Distrib 8.4.2, for Win64 (x86_64)
--
-- Host: 157.20.83.145    Database: restaurant
-- ------------------------------------------------------
-- Server version	8.0.39-0ubuntu0.20.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `category`
--

DROP TABLE IF EXISTS `category`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `category` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UK46ccwnsi9409t36lurvtyljak` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `category`
--

LOCK TABLES `category` WRITE;
/*!40000 ALTER TABLE `category` DISABLE KEYS */;
INSERT INTO `category` VALUES (1,'Appetizer'),(3,'Desserts'),(4,'Drinks'),(2,'Main Course');
/*!40000 ALTER TABLE `category` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `customer`
--

DROP TABLE IF EXISTS `customer`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `customer` (
  `customer_id` bigint NOT NULL AUTO_INCREMENT,
  `address` varchar(255) DEFAULT NULL,
  `date_of_birth` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `first_name` varchar(255) DEFAULT NULL,
  `last_name` varchar(255) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `phone` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`customer_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `customer`
--

LOCK TABLES `customer` WRITE;
/*!40000 ALTER TABLE `customer` DISABLE KEYS */;
INSERT INTO `customer` VALUES (1,'HCM','2024-12-12','khoa@gmail.com','Võ Minh ','Khoa','$2a$10$yw8e96VAM2tL3wN.NwaGAeDmBOpz6lniz7SyhB4uddSq3D7YtFw4G','0978586850'),(2,'a','2004-11-11','admin@gmail.com','Nhân','Nguyễn Văn','$2a$10$462Po/CkyyoB1Na.owLii.LEp2CbuOrTEnaTkM4hn3lSm4uaFB.m.','0365235789'),(3,'HCm','2004-11-11','noinfo@default.com','noinfo','noinfo','$2a$10$BMb.cRz09gdECqbyfJ5Te.gEZk2DDFJxO5/cfT08JtjzCmYwBXEmq','+84386056830');
/*!40000 ALTER TABLE `customer` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `customer_order`
--

DROP TABLE IF EXISTS `customer_order`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `customer_order` (
  `id` varchar(255) NOT NULL,
  `comment` varchar(255) DEFAULT NULL,
  `order_date` datetime(6) DEFAULT NULL,
  `order_method` enum('CASH','MOMO','VNPAY') DEFAULT NULL,
  `order_status` enum('CANCELED','COMPLETED','PAID','PENDING','UNPAID') DEFAULT NULL,
  `rating` int NOT NULL,
  `total_amount` double DEFAULT NULL,
  `customer_id` bigint DEFAULT NULL,
  `dining_table_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FKf9abd30bhiqvugayxlpq8ryq9` (`customer_id`),
  KEY `FKhkhw19ph0itlyfiy28fghwuuu` (`dining_table_id`),
  CONSTRAINT `FKf9abd30bhiqvugayxlpq8ryq9` FOREIGN KEY (`customer_id`) REFERENCES `customer` (`customer_id`),
  CONSTRAINT `FKhkhw19ph0itlyfiy28fghwuuu` FOREIGN KEY (`dining_table_id`) REFERENCES `dining_table` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `customer_order`
--

LOCK TABLES `customer_order` WRITE;
/*!40000 ALTER TABLE `customer_order` DISABLE KEYS */;
INSERT INTO `customer_order` VALUES ('2024120612279',NULL,'2024-12-06 16:34:16.260491','CASH','COMPLETED',0,125000,1,1),('2024120630567',NULL,'2024-11-06 15:28:23.202989','CASH','COMPLETED',0,85000,3,5),('2024120632366',NULL,'2024-11-02 15:27:16.416583','CASH','COMPLETED',0,250000,3,3),('2024120632621',NULL,'2024-11-03 15:26:37.866482','CASH','COMPLETED',0,95000,3,6),('2024120632710',NULL,'2024-11-11 15:28:09.932687','CASH','COMPLETED',0,80000,3,5),('2024120633128',NULL,'2024-11-05 15:28:45.947093','CASH','COMPLETED',0,95000,3,5),('2024120633522',NULL,'2024-11-12 15:26:14.738756','CASH','COMPLETED',0,80000,3,1),('2024120634926',NULL,'2024-12-06 15:27:34.588129','CASH','COMPLETED',0,80000,3,2),('2024120636275',NULL,'2024-12-06 15:27:44.890964','CASH','COMPLETED',0,50000,3,4),('2024120637035',NULL,'2024-12-06 15:25:57.189998','CASH','COMPLETED',0,190000,3,1),('2024120637144',NULL,'2024-12-06 15:26:48.817867','CASH','COMPLETED',0,300000,3,5),('2024120638754',NULL,'2024-12-06 15:28:34.893369','CASH','COMPLETED',0,95000,3,3),('2024120638869',NULL,'2024-12-06 15:27:57.527910','CASH','COMPLETED',0,75000,3,5),('2024120639054',NULL,'2024-12-06 15:27:04.367530','CASH','COMPLETED',0,440000,3,4),('2024120639149','rất ngon','2024-12-06 16:47:59.651850','CASH','COMPLETED',5,80000,3,4),('2024120639872',NULL,'2024-12-06 15:26:26.762658','CASH','COMPLETED',0,30000,3,6);
/*!40000 ALTER TABLE `customer_order` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dining_table`
--

DROP TABLE IF EXISTS `dining_table`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dining_table` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `capacity` int NOT NULL,
  `qr_code_url` varchar(255) NOT NULL,
  `status` enum('AVAILABLE','OCCUPIED','RESERVED','UNAVAILABLE') NOT NULL,
  `table_number` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UKsn1m34gmwngjikke0cfirfc03` (`table_number`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dining_table`
--

LOCK TABLES `dining_table` WRITE;
/*!40000 ALTER TABLE `dining_table` DISABLE KEYS */;
INSERT INTO `dining_table` VALUES (1,1,'http://res.cloudinary.com/driu62xj1/image/upload/v1733404528/eg0plklxuioon480ro6l.png','AVAILABLE',1),(2,4,'http://res.cloudinary.com/driu62xj1/image/upload/v1733479312/ewhspgadfxafalrmx3iu.png','AVAILABLE',2),(3,4,'http://res.cloudinary.com/driu62xj1/image/upload/v1733486864/kd6viygsausjzcio1xcv.png','AVAILABLE',3),(4,4,'http://res.cloudinary.com/driu62xj1/image/upload/v1733486878/iv8sirilp0ukj5oxnunp.png','AVAILABLE',4),(5,5,'http://res.cloudinary.com/driu62xj1/image/upload/v1733486888/m3yv6jrdqqr5ukmlltv6.png','AVAILABLE',5),(6,6,'http://res.cloudinary.com/driu62xj1/image/upload/v1733486894/jdkrv9xublnh0zwy0o4a.png','AVAILABLE',6);
/*!40000 ALTER TABLE `dining_table` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `discount`
--

DROP TABLE IF EXISTS `discount`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `discount` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `code` varchar(255) NOT NULL,
  `end_date` date NOT NULL,
  `is_active` bit(1) NOT NULL,
  `max_amount` decimal(38,2) NOT NULL,
  `percentage` int NOT NULL,
  `start_date` date NOT NULL,
  `times_used` int NOT NULL,
  `usage_limit` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UKi14w897ofrtv43vbx44rtv01u` (`code`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `discount`
--

LOCK TABLES `discount` WRITE;
/*!40000 ALTER TABLE `discount` DISABLE KEYS */;
INSERT INTO `discount` VALUES (1,'120','2024-12-21',_binary '',20000.00,20,'2024-12-05',0,2),(2,'121','2024-12-28',_binary '',300000.00,30,'2024-12-02',0,10),(3,'1','2024-12-20',_binary '',300000.00,30,'2024-12-04',0,10);
/*!40000 ALTER TABLE `discount` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dish`
--

DROP TABLE IF EXISTS `dish`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dish` (
  `dish_id` bigint NOT NULL AUTO_INCREMENT,
  `cost` double NOT NULL,
  `description` varchar(500) DEFAULT NULL,
  `image` varchar(255) DEFAULT NULL,
  `name` varchar(100) NOT NULL,
  `price` double NOT NULL,
  `category_id` bigint NOT NULL,
  PRIMARY KEY (`dish_id`),
  UNIQUE KEY `UKr7g2l08wdh3uv3gvurli4s1bx` (`name`),
  KEY `FK3h7qfevodvyk24ss68mwu8ap6` (`category_id`),
  CONSTRAINT `FK3h7qfevodvyk24ss68mwu8ap6` FOREIGN KEY (`category_id`) REFERENCES `category` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dish`
--

LOCK TABLES `dish` WRITE;
/*!40000 ALTER TABLE `dish` DISABLE KEYS */;
INSERT INTO `dish` VALUES (1,34300,'Pho','http://res.cloudinary.com/driu62xj1/image/upload/v1733476290/zzazs1e0ceht1eelvajs.jpg','Pho',30000,2),(2,29150,' Bánh mì bơ tỏi ','http://res.cloudinary.com/driu62xj1/image/upload/v1733476397/fobmbqvuynx0ghenh05o.jpg','Bánh mì bơ tỏi',50000,1),(3,21790,'Gỏi mực','http://res.cloudinary.com/driu62xj1/image/upload/v1733476413/bpyt4rizmetzydlh7dln.jpg','Gỏi mực',45000,1),(4,50825,'cá tươi','http://res.cloudinary.com/driu62xj1/image/upload/v1733476488/wp7g705usv5uhrtzsza2.jpg','Cá hồi áp chảo sốt tiêu xanh',250000,1),(5,31500,'Cocktail','http://res.cloudinary.com/driu62xj1/image/upload/v1733476511/oxmkl880urtyvizpeam2.jpg','Cocktail',100000,4),(6,5000,'Nước suối','http://res.cloudinary.com/driu62xj1/image/upload/v1733476589/pyprxuapgoad0uuxp4dw.jpg','Nước suối',20000,4),(7,30000,'Coffee','http://res.cloudinary.com/driu62xj1/image/upload/v1733476654/zzgnzbl0xfdchty5khi8.jpg','Coffee',85000,4),(9,75005,'Bánh xèo','http://res.cloudinary.com/driu62xj1/image/upload/v1733487148/okrcmrnwhvll3u7lms6x.jpg','Bánh xèo',200000,2),(10,56024,'Bún riêu cua','http://res.cloudinary.com/driu62xj1/image/upload/v1733487170/m1zow7cqwhqzilcgry8b.jpg','Bún riêu cua',250000,2),(11,67935,'Gỏi cuốn','http://res.cloudinary.com/driu62xj1/image/upload/v1733487193/bictffvn7gqnqp9caq5v.jpg','Gỏi cuốn',190000,2),(12,98653,'Cơm tấm','http://res.cloudinary.com/driu62xj1/image/upload/v1733487286/huxvzobcxr143kplexak.jpg','Cơm tấm',300000,2);
/*!40000 ALTER TABLE `dish` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `employee`
--

DROP TABLE IF EXISTS `employee`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `employee` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `email` varchar(255) DEFAULT NULL,
  `image` varchar(255) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `phone` varchar(255) DEFAULT NULL,
  `position` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `employee`
--

LOCK TABLES `employee` WRITE;
/*!40000 ALTER TABLE `employee` DISABLE KEYS */;
INSERT INTO `employee` VALUES (1,'admin@gmail.com',NULL,'admin','$2a$10$zwyzjIIqXNE2LsR2pGviWOYaJXMWaAGrBH9UFSLK3TilyL6.aDMJa',NULL,'ADMIN'),(5,'staff@gmail.com','http://res.cloudinary.com/driu62xj1/image/upload/v1733493990/nadmnzctjsho58t3kqkk.jpg','Nguyễn Văn A','$2a$10$gx/1edUh3JZDNMrcCALfYeQr7BmyFCkFwry6rYUo0W3sEpXG1BsIG','0123456789','STAFF'),(6,'chef@gmail.com','http://res.cloudinary.com/driu62xj1/image/upload/v1733494041/ijhd5dyeavviswbdl2e3.jpg','Chef Num 1','$2a$10$LtXGNfYYEtV4cqTwSlxwfuH7eHQe0N2Sqc/.mQ7CrXdR.6/UHvuJC','0123456789','CHEF'),(7,'staff1@gmail.com','http://res.cloudinary.com/driu62xj1/image/upload/v1733494070/orjxuolsscgxeeyzn5v6.webp','Nguyễn Văn B','$2a$10$M0WL/Vnrn8v480GxOPb2I.8EdB1LgV6VLcjoygdYHxaSHNq/Hmu3a','0123456789','STAFF'),(8,'staff2@gmail.com','http://res.cloudinary.com/driu62xj1/image/upload/v1733494108/gsdatorga4l4a56cuvsm.jpg','Nguyễn Văn C','$2a$10$2rlDkrokJLUaK5/YaJsmT..NuP87TcFu05Na7rdK9p08w68FTkE1y','0123456789','STAFF'),(9,'staff3@gmail.com','http://res.cloudinary.com/driu62xj1/image/upload/v1733494135/klkr6ehitp1anfaezvqp.jpg','Nguyễn Văn D','$2a$10$G7MKGUHCyu7MFqV3MZRP.eGxC4fIxQv5ld4pi8lUajV08fvyZ8TKm','0123456789','STAFF'),(10,'staff4@gmail.com','http://res.cloudinary.com/driu62xj1/image/upload/v1733494179/t9kdv1p5uz0nfyw3pmrk.jpg','Nguyễn Văn E','$2a$10$nKLqy0tLpFdMw5nwLRckOOc/Gvw5uWUeLrfa/.QUOrHQWHARj5CVO','0123456789','STAFF'),(11,'chef1@gmail.com','http://res.cloudinary.com/driu62xj1/image/upload/v1733494208/ytbz4czgzdhweswlaak0.jpg','Chef Num 2','$2a$10$AThlgz1wMNIZax3g9f.br.N7LofvFhmZnpYSAYk0Dy7dIVpgx2/lm','0123456789','CHEF'),(14,'staff5@gmail.com','http://res.cloudinary.com/driu62xj1/image/upload/v1733506597/f9bls6wmgzkxk7eeotxt.jpg','Nguyễn Văn F','$2a$10$SYemgs5bCMjjPdx7CVHehuTngIzT.bBcb/Tk.0JdwSz8oQQir/Qrm','0123456789','STAFF');
/*!40000 ALTER TABLE `employee` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `inventory`
--

DROP TABLE IF EXISTS `inventory`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `inventory` (
  `inventory_id` bigint NOT NULL AUTO_INCREMENT,
  `description` varchar(255) DEFAULT NULL,
  `item_name` varchar(255) DEFAULT NULL,
  `quantity` int NOT NULL,
  `unit` varchar(255) DEFAULT NULL,
  `unit_price` double DEFAULT NULL,
  `supplier_id` bigint NOT NULL,
  PRIMARY KEY (`inventory_id`),
  KEY `FKe0810rp6mmsbj1f46yhc4h7vb` (`supplier_id`),
  CONSTRAINT `FKe0810rp6mmsbj1f46yhc4h7vb` FOREIGN KEY (`supplier_id`) REFERENCES `supplier` (`supplier_id`)
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `inventory`
--

LOCK TABLES `inventory` WRITE;
/*!40000 ALTER TABLE `inventory` DISABLE KEYS */;
INSERT INTO `inventory` VALUES (1,'Táo tươi, nhập khẩu từ Đà Lạt','Táo',49980,'g',70,1),(2,'Thịt bò phi lê, thích hợp làm bò bít tết','Thịt bò',29920,'g',200,2),(3,'Sô cô la nguyên chất, dùng làm bánh ngọt','Sô cô la',99943,'g',350,3),(4,'Cà rốt tươi, được trồng tại Gia Lai','Cà rốt',59940,'g',40,4),(5,'Xà lách sạch, thu hoạch tại Đà Lạt','Xà lách',39943,'g',40,5),(6,'Hành lá tươi, gia vị cần thiết trong món ăn Việt','Hành lá',24940,'g',30,1),(7,'Gạo thơm hảo hạng, thích hợp nấu cơm và xôi','Gạo',499943,'g',15,2),(8,'Nước mắm cốt nhĩ, gia vị đặc trưng của Việt Nam','Nước mắm',99940,'ml',20,3),(9,'Bột mì đa dụng, nguyên liệu chính cho bánh mì','Bột mì',199940,'g',20,4),(10,'Đường cát trắng, dùng trong các món tráng miệng','Đường',300000,'g',10,5),(11,'Muối biển sạch, gia vị phổ biến trong mọi món ăn','Muối',100000,'g',500,1),(12,'Cá hồi tươi nhập khẩu, thích hợp làm sushi','Cá hồi',19940,'g',400,2),(13,'Tôm sú tươi, sử dụng trong các món chiên và hấp','Tôm sú',30000,'g',280,3),(14,'Gừng tươi, gia vị không thể thiếu trong các món Việt','Gừng',15000,'g',5,4),(15,'Ớt tươi đỏ, nguyên liệu cho các món cay','Ớt',25000,'g',60,5),(16,'Ớt bột nhập khẩu từ Hàn Quốc,','Gia vị ớt bột',30000,'gói',10000,2);
/*!40000 ALTER TABLE `inventory` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `order_item`
--

DROP TABLE IF EXISTS `order_item`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `order_item` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `cost` double NOT NULL,
  `order_status` enum('CANCELED','COMPLETED','PAID','PENDING','UNPAID') DEFAULT NULL,
  `price` double NOT NULL,
  `quantity` int NOT NULL,
  `dish_id` bigint DEFAULT NULL,
  `order_id` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FKs7aplknkrukmckr29wijlvcy1` (`dish_id`),
  KEY `FKgv4bnmo7cbib2nh0b2rw9yvir` (`order_id`),
  CONSTRAINT `FKgv4bnmo7cbib2nh0b2rw9yvir` FOREIGN KEY (`order_id`) REFERENCES `customer_order` (`id`),
  CONSTRAINT `FKs7aplknkrukmckr29wijlvcy1` FOREIGN KEY (`dish_id`) REFERENCES `dish` (`dish_id`)
) ENGINE=InnoDB AUTO_INCREMENT=59 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `order_item`
--

LOCK TABLES `order_item` WRITE;
/*!40000 ALTER TABLE `order_item` DISABLE KEYS */;
INSERT INTO `order_item` VALUES (16,29150,'COMPLETED',50000,2,2,'2024120637035'),(17,21790,'COMPLETED',45000,2,3,'2024120637035'),(18,56024,'COMPLETED',250000,1,10,'2024120637035'),(19,34300,'COMPLETED',30000,1,1,'2024120633522'),(20,29150,'COMPLETED',50000,1,2,'2024120633522'),(21,56024,'COMPLETED',250000,1,10,'2024120633522'),(22,34300,'COMPLETED',30000,1,1,'2024120639872'),(23,98653,'COMPLETED',300000,1,12,'2024120639872'),(24,29150,'COMPLETED',50000,1,2,'2024120632621'),(25,21790,'COMPLETED',45000,1,3,'2024120632621'),(26,98653,'COMPLETED',300000,1,12,'2024120632621'),(27,98653,'COMPLETED',300000,1,12,'2024120637144'),(28,29150,'COMPLETED',50000,1,2,'2024120637144'),(29,67935,'COMPLETED',190000,1,11,'2024120639054'),(30,56024,'PENDING',250000,1,10,'2024120639054'),(31,75005,'PENDING',200000,1,9,'2024120639054'),(32,29150,'PENDING',50000,5,2,'2024120632366'),(33,34300,'PENDING',30000,1,1,'2024120634926'),(34,29150,'PENDING',50000,1,2,'2024120634926'),(35,21790,'PENDING',45000,1,3,'2024120634926'),(36,29150,'PENDING',50000,1,2,'2024120636275'),(37,5000,'PENDING',20000,1,6,'2024120636275'),(38,21790,'PENDING',45000,1,3,'2024120638869'),(39,34300,'PENDING',30000,1,1,'2024120638869'),(40,31500,'PENDING',100000,1,5,'2024120638869'),(41,34300,'PENDING',30000,1,1,'2024120632710'),(42,29150,'PENDING',50000,1,2,'2024120632710'),(43,31500,'PENDING',100000,1,5,'2024120632710'),(44,30000,'PENDING',85000,1,7,'2024120630567'),(45,75005,'PENDING',200000,1,9,'2024120630567'),(46,29150,'PENDING',50000,1,2,'2024120638754'),(47,21790,'PENDING',45000,1,3,'2024120638754'),(48,56024,'PENDING',250000,1,10,'2024120638754'),(49,29150,'PENDING',50000,1,2,'2024120633128'),(50,21790,'PENDING',45000,1,3,'2024120633128'),(51,5000,'PENDING',20000,1,6,'2024120633128'),(52,34300,'PENDING',30000,1,1,'2024120612279'),(53,29150,'PENDING',50000,1,2,'2024120612279'),(54,21790,'PENDING',45000,1,3,'2024120612279'),(55,5000,'PENDING',20000,1,6,'2024120612279'),(56,34300,'PENDING',30000,1,1,'2024120639149'),(57,29150,'PENDING',50000,1,2,'2024120639149'),(58,21790,'PENDING',45000,1,3,'2024120639149');
/*!40000 ALTER TABLE `order_item` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `otp`
--

DROP TABLE IF EXISTS `otp`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `otp` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `expiry_time` datetime(6) DEFAULT NULL,
  `is_used` bit(1) NOT NULL,
  `otp_code` varchar(255) DEFAULT NULL,
  `phone_number` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `otp`
--

LOCK TABLES `otp` WRITE;
/*!40000 ALTER TABLE `otp` DISABLE KEYS */;
INSERT INTO `otp` VALUES (1,'2024-12-05 14:11:36.324807',_binary '\0','438957','0978586850'),(2,'2024-12-05 14:12:32.092353',_binary '','836797','+84386056830'),(3,'2024-12-06 16:27:53.073011',_binary '\0','587649','+84386056830'),(4,'2024-12-06 16:28:41.958252',_binary '','920391','+84386056830');
/*!40000 ALTER TABLE `otp` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `recipe`
--

DROP TABLE IF EXISTS `recipe`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `recipe` (
  `recipe_id` bigint NOT NULL AUTO_INCREMENT,
  `quantity_required` int NOT NULL,
  `dish_id` bigint NOT NULL,
  `inventory_id` bigint NOT NULL,
  PRIMARY KEY (`recipe_id`),
  KEY `FK6gd6sjjumfpbk8w03lv6ohwb5` (`dish_id`),
  KEY `FKqr8ypyincg2gje81jnt3bqv8o` (`inventory_id`),
  CONSTRAINT `FK6gd6sjjumfpbk8w03lv6ohwb5` FOREIGN KEY (`dish_id`) REFERENCES `dish` (`dish_id`),
  CONSTRAINT `FKqr8ypyincg2gje81jnt3bqv8o` FOREIGN KEY (`inventory_id`) REFERENCES `inventory` (`inventory_id`)
) ENGINE=InnoDB AUTO_INCREMENT=321 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `recipe`
--

LOCK TABLES `recipe` WRITE;
/*!40000 ALTER TABLE `recipe` DISABLE KEYS */;
INSERT INTO `recipe` VALUES (207,200,5,1),(208,50,5,3),(226,99,1,2),(227,15,1,4),(228,30,1,5),(229,50,1,7),(230,10,1,8),(231,190,1,9),(232,10,1,10),(233,10,1,11),(234,10,1,13),(235,10,1,14),(241,50,2,1),(242,80,2,2),(243,10,2,3),(244,10,2,4),(245,10,2,5),(246,10,2,9),(247,10,2,10),(248,10,2,11),(249,10,2,14),(285,99,3,4),(286,19,3,5),(287,9,3,8),(288,9,3,10),(289,20,3,11),(290,10,3,12),(291,10,3,13),(311,49,4,2),(312,20,4,4),(313,30,4,5),(314,10,4,6),(315,13,4,7),(316,94,4,8),(317,20,4,12),(318,100,4,13),(319,10,4,14),(320,10,4,15);
/*!40000 ALTER TABLE `recipe` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `reservation`
--

DROP TABLE IF EXISTS `reservation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `reservation` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `customer_name` varchar(255) DEFAULT NULL,
  `date_to_come` date DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `note` varchar(255) DEFAULT NULL,
  `number_of_persons` int DEFAULT NULL,
  `status` enum('CANCELLED','CONFIRMED','FINISHED','PENDING') DEFAULT NULL,
  `time_to_come` time(6) DEFAULT NULL,
  `table_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FKarab6o324oagupooctuexfwsi` (`table_id`),
  CONSTRAINT `FKarab6o324oagupooctuexfwsi` FOREIGN KEY (`table_id`) REFERENCES `dining_table` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `reservation`
--

LOCK TABLES `reservation` WRITE;
/*!40000 ALTER TABLE `reservation` DISABLE KEYS */;
INSERT INTO `reservation` VALUES (1,'loc','2024-12-12','lantubuon08@gmail.com','ko ăn cay',4,'CANCELLED','09:31:00.000000',2),(2,'Võ Minh Khoa','2024-12-07','v.minhkhoa123456@gmail.com','Web',2,'CONFIRMED','20:15:00.000000',6),(3,'loc','2024-12-07','loc@gmail.com','ko có',4,'CONFIRMED','20:16:00.000000',5),(4,'loc1','2024-12-21','loc@gmail.com','',3,'CONFIRMED','20:19:00.000000',1),(5,'loc','2024-12-07','loc@gmail.com','',3,'CANCELLED','23:39:00.000000',2);
/*!40000 ALTER TABLE `reservation` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `salary`
--

DROP TABLE IF EXISTS `salary`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `salary` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `bonus` double DEFAULT NULL,
  `hourly_rate` double DEFAULT NULL,
  `pay_date` date DEFAULT NULL,
  `status` enum('PAID','PENDING') DEFAULT NULL,
  `total_hours_worked` double DEFAULT NULL,
  `total_salary` double DEFAULT NULL,
  `employee_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FKnlnv3jbyvbiu8ci59r3btlk00` (`employee_id`),
  CONSTRAINT `FKnlnv3jbyvbiu8ci59r3btlk00` FOREIGN KEY (`employee_id`) REFERENCES `employee` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=31 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `salary`
--

LOCK TABLES `salary` WRITE;
/*!40000 ALTER TABLE `salary` DISABLE KEYS */;
/*!40000 ALTER TABLE `salary` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `schedule`
--

DROP TABLE IF EXISTS `schedule`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `schedule` (
  `schedule_id` bigint NOT NULL AUTO_INCREMENT,
  `end_time` time(6) DEFAULT NULL,
  `start_time` time(6) DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `working_date` date DEFAULT NULL,
  `employee_id` bigint DEFAULT NULL,
  `shift_id` bigint DEFAULT NULL,
  PRIMARY KEY (`schedule_id`),
  KEY `FKsodsj8c282vagj766ll9g8tdc` (`employee_id`),
  KEY `FKajqm53soraqn6bpdsfvxtbv52` (`shift_id`),
  CONSTRAINT `FKajqm53soraqn6bpdsfvxtbv52` FOREIGN KEY (`shift_id`) REFERENCES `shift` (`shift_id`),
  CONSTRAINT `FKsodsj8c282vagj766ll9g8tdc` FOREIGN KEY (`employee_id`) REFERENCES `employee` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=566 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `schedule`
--

LOCK TABLES `schedule` WRITE;
/*!40000 ALTER TABLE `schedule` DISABLE KEYS */;
INSERT INTO `schedule` VALUES (482,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-16',5,1),(483,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-16',5,4),(484,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-17',5,1),(485,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-17',5,4),(486,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-18',5,1),(487,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-18',5,4),(488,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-19',5,2),(489,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-20',5,2),(490,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-21',5,2),(491,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-22',5,1),(492,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-22',5,4),(493,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-16',7,1),(494,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-16',7,4),(495,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-17',7,1),(496,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-17',7,4),(497,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-18',7,2),(498,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-19',7,1),(499,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-19',7,4),(500,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-20',7,2),(501,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-21',7,1),(502,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-21',7,4),(503,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-22',7,2),(504,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-16',8,1),(505,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-16',8,4),(506,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-17',8,2),(507,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-18',8,1),(508,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-18',8,4),(509,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-19',8,1),(510,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-19',8,4),(511,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-20',8,1),(512,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-20',8,4),(513,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-21',8,2),(514,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-22',8,2),(515,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-16',9,2),(516,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-17',9,2),(517,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-18',9,2),(518,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-19',9,2),(519,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-20',9,1),(520,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-20',9,4),(521,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-21',9,1),(522,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-21',9,4),(523,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-22',9,1),(524,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-22',9,4),(525,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-16',10,2),(526,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-17',10,2),(527,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-18',10,2),(528,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-19',10,1),(529,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-19',10,4),(530,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-20',10,1),(531,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-20',10,4),(532,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-21',10,2),(533,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-22',10,1),(534,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-22',10,4),(535,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-16',14,2),(536,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-17',14,1),(537,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-17',14,4),(538,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-18',14,1),(539,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-18',14,4),(540,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-19',14,2),(541,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-20',14,2),(542,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-21',14,1),(543,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-21',14,4),(544,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-22',14,2),(545,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-16',6,1),(546,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-16',6,4),(547,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-17',6,1),(548,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-17',6,4),(549,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-18',6,1),(550,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-18',6,4),(551,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-19',6,2),(552,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-20',6,2),(553,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-21',6,2),(554,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-22',6,2),(555,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-16',11,2),(556,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-17',11,2),(557,'15:00:00.000000','11:00:00.000000','DRAFF','2024-12-18',11,2),(558,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-19',11,1),(559,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-19',11,4),(560,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-20',11,1),(561,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-20',11,4),(562,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-21',11,1),(563,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-21',11,4),(564,'11:00:00.000000','07:00:00.000000','DRAFF','2024-12-22',11,1),(565,'21:00:00.000000','17:00:00.000000','DRAFF','2024-12-22',11,4);
/*!40000 ALTER TABLE `schedule` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `shift`
--

DROP TABLE IF EXISTS `shift`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `shift` (
  `shift_id` bigint NOT NULL AUTO_INCREMENT,
  `available` int DEFAULT NULL,
  `end_time` time(6) DEFAULT NULL,
  `is_active` bit(1) NOT NULL,
  `max_registration` int NOT NULL,
  `shift_name` varchar(255) DEFAULT NULL,
  `shift_type` enum('FIXED','OPEN','REGULAR') DEFAULT NULL,
  `start_time` time(6) DEFAULT NULL,
  `working_date` date DEFAULT NULL,
  `employee_id` bigint DEFAULT NULL,
  PRIMARY KEY (`shift_id`),
  KEY `FKg9ycreft1sv2jjvkno3dn3fqy` (`employee_id`),
  CONSTRAINT `FKg9ycreft1sv2jjvkno3dn3fqy` FOREIGN KEY (`employee_id`) REFERENCES `employee` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shift`
--

LOCK TABLES `shift` WRITE;
/*!40000 ALTER TABLE `shift` DISABLE KEYS */;
INSERT INTO `shift` VALUES (1,0,'11:00:00.000000',_binary '\0',999,'Morning','REGULAR','07:00:00.000000','2024-12-06',1),(2,0,'15:00:00.000000',_binary '\0',999,'Lunch','REGULAR','11:00:00.000000','2024-12-06',1),(3,9,'21:00:00.000000',_binary '\0',12,'Open Shift 11/12/2024','OPEN','17:00:00.000000','2024-12-10',1),(4,0,'21:00:00.000000',_binary '\0',999,'Evening','REGULAR','17:00:00.000000','2024-12-06',1),(5,8,'11:00:00.000000',_binary '\0',9,'Open Shift 11/12/2024','OPEN','09:00:00.000000','2024-12-11',1),(6,999,'09:00:00.000000',_binary '\0',999,'Fixed 1','FIXED','07:00:00.000000','2024-12-06',1);
/*!40000 ALTER TABLE `shift` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `supplier`
--

DROP TABLE IF EXISTS `supplier`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `supplier` (
  `supplier_id` bigint NOT NULL AUTO_INCREMENT,
  `address` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `notes` varchar(255) DEFAULT NULL,
  `phone` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`supplier_id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `supplier`
--

LOCK TABLES `supplier` WRITE;
/*!40000 ALTER TABLE `supplier` DISABLE KEYS */;
INSERT INTO `supplier` VALUES (1,'456 Main St, Hanoi','foodco@example.com','Food Co.',NULL,'0912345678'),(2,'789 Oak St, Hanoi','beefsuppliers@example.com','Beef Suppliers',NULL,'0912345679'),(3,'101 Pine St, Hanoi','sweettreats@example.com','Sweet Treats',NULL,'0912345680'),(4,'202 Cedar Rd, Hanoi','veggieworld@example.com','Veggie World',NULL,'0912345681'),(5,'303 Elm St, Hanoi','fruitfarm@example.com','Fruit Farm',NULL,'0912345682');
/*!40000 ALTER TABLE `supplier` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-12-07  1:11:13
