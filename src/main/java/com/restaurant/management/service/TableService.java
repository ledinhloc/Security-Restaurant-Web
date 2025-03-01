package com.restaurant.management.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.restaurant.management.enums.TableStatus;
import com.restaurant.management.model.DiningTable;
import com.restaurant.management.repository.TableRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Service
public class TableService {
    @Autowired
    private TableRepository tableRepository;

    @Autowired
    private StorageService storageService;

    public List<DiningTable> getAllTables() {
        return tableRepository.findAll();
    }

    public Page<DiningTable> getTablesWithPagination(int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size);
        return tableRepository.findAll(pageRequest);
    }

    public Optional<DiningTable> getTableById(Long id) {
        return tableRepository.findById(id);
    }

    public Long getTableNumberByTableId(Long tableId) {
        return tableRepository.getTableNumberById(tableId);
    }

    public DiningTable save(DiningTable table) {
        return tableRepository.save(table);
    }

    public void updateTableStatus(Long tableId, TableStatus status) {
        DiningTable table = tableRepository.findById(tableId).get();
        table.setStatus(status);
        tableRepository.save(table);
    }

    public DiningTable createTable(DiningTable diningTable, HttpServletRequest request) throws WriterException, IOException {
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();

        String tableUrl = scheme + "://" + serverName + ":" + serverPort + "/tables/" + diningTable.getTableNumber();

        ByteArrayOutputStream qrCodeStream = new ByteArrayOutputStream();
        writeQRCodeImageToStream(tableUrl, diningTable.getTableNumber().toString(), qrCodeStream);

        String qrCodeUrl = storageService.uploadImage(qrCodeStream.toByteArray());

        diningTable.setQrCodeUrl(qrCodeUrl);

        return tableRepository.save(diningTable);
    }

    public void updateTable(Long id, DiningTable diningTable) {
        DiningTable existingTable = tableRepository.findById(id).orElseThrow(() ->
                new IllegalArgumentException("Invalid table Id:" + id));

        existingTable.setTableNumber(diningTable.getTableNumber());
        existingTable.setStatus(diningTable.getStatus());

        tableRepository.save(existingTable);
    }

    public void deleteTable(Long id) {
        tableRepository.deleteById(id);
    }

//    public List<DiningTable> findAvailableTables(LocalDate date, LocalTime timeToCome) {
//        return tableRepository.findAvailableTables(date, timeToCome, 1);
//    }

    private void writeQRCodeImageToStream(String text, String tableNumber, ByteArrayOutputStream stream) throws WriterException, IOException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, 250, 250);

        BufferedImage qrImage = MatrixToImageWriter.toBufferedImage(bitMatrix);

        BufferedImage combinedImage = new BufferedImage(250, 300, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = combinedImage.createGraphics();

        g.setColor(Color.WHITE);
        g.fillRect(0, 0, 250, 300);
        g.drawImage(qrImage, 0, 0, null);

        // Cấu hình font và vẽ text
        g.setColor(Color.BLACK);
        g.setFont(new Font("Arial", Font.BOLD, 16));
        String text1 = "Bàn số " + tableNumber;
        String text2 = "Quét QR Code để đặt món";

        // Căn giữa và vẽ text
        FontMetrics metrics = g.getFontMetrics();
        int x1 = (250 - metrics.stringWidth(text1)) / 2;
        int x2 = (250 - metrics.stringWidth(text2)) / 2;
        g.drawString(text1, x1, 250);
        g.drawString(text2, x2, 270);

        g.dispose();

        // Ghi BufferedImage vào stream
        ImageIO.write(combinedImage, "PNG", stream);
    }


}
