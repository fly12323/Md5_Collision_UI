package org.example.md5;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class UrlDecodeAndMd5 {
    public static void main(String[] args) {
        String input = "12345%80%00admin";

        try {
            // 1. URL解码（使用ISO-8859-1避免字节丢失）
            String decoded = URLDecoder.decode(input, StandardCharsets.ISO_8859_1);

            // 2. 将解码后的字符串转换为字节数组（保持原始字节）
            byte[] bytes = decoded.getBytes(StandardCharsets.ISO_8859_1);

            // 3. 计算MD5哈希
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(bytes);

            // 4. 将MD5结果转换为十六进制字符串
            String hex = bytesToHex(digest);

            System.out.println("MD5结果: " + hex);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    // 辅助方法：将字节数组转为十六进制字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = String.format("%02x", b & 0xFF);
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
