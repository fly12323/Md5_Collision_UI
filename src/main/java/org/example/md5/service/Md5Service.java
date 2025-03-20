package org.example.md5.service;

import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MD5 加密服务
 * 作用：提供 MD5 加密操作，支持普通字符和 URL 类型的加密
 */
public class Md5Service {

    /**
     * 计算 MD5 值（使用指定字符集）
     */
    public String computeMD5(String input, Charset charset) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(charset));
            StringBuilder hexString = new StringBuilder();
            for (byte b : digest) {
                hexString.append(String.format("%02x", b & 0xFF));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException ex) {
            return "MD5 算法不可用: " + ex.getMessage();
        }
    }

    /**
     * 加密方法，根据输入类型处理
     * @param input 输入字符串
     * @param type  类型（普通字符或 URL）
     * @return 加密结果
     */
    public String encrypt(String input, String type) {
        String processedInput = input;
        Charset processingCharset = StandardCharsets.UTF_8;

        if ("URL".equals(type)) {
            try {
                processedInput = URLDecoder.decode(input, StandardCharsets.ISO_8859_1.name());
                processingCharset = StandardCharsets.ISO_8859_1;
            } catch (Exception e) {
                return "URL 解码失败: " + e.getMessage();
            }
        }
        String hash = computeMD5(processedInput, processingCharset);
        StringBuilder result = new StringBuilder();
        result.append("输入类型: ").append(type).append("\n");
        if ("URL".equals(type)) {
            result.append("URL 解码后原始数据: ").append(processedInput).append("\n");
        }
        result.append("MD5: ").append(hash);
        return result.toString();
    }
}
