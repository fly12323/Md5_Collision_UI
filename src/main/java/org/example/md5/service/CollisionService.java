package org.example.md5.service;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * MD5 碰撞攻击服务
 * 作用：提供单次碰撞、双次碰撞、后缀碰撞以及强碰撞功能
 */
public class CollisionService {

    /**
     * 根据字符类型生成随机字符串
     * @param len 随机字符串长度
     * @param charType 字符类型，例如 "全部"、"数字"、"字母"
     * @return 随机字符串
     */
    private String generateRandomString(int len, String charType) {
        String allowedChars = switch (charType) {
            case "数字" -> "0123456789";
            case "字母" -> "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            default -> "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        };
        Random rand = new Random();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(allowedChars.charAt(rand.nextInt(allowedChars.length())));
        }
        return sb.toString();
    }

    /**
     * 计算 MD5 值（使用 UTF-8 编码）
     */
    private String computeMD5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : digest) {
                hexString.append(String.format("%02x", b & 0xff));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    /**
     * 单次碰撞：寻找一个随机字符串，使其 MD5 指定位置子串匹配目标值
     * @param target 目标子串
     * @param start 开始位置
     * @param randLen 随机字符串长度
     * @param charType 字符类型（“全部”、“数字”、“字母”）
     */
    public String singleCollision(String target, int start, int randLen, String charType) {
        final AtomicBoolean found = new AtomicBoolean(false);
        final StringBuilder result = new StringBuilder();
        int cpus = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(cpus);

        Runnable task = () -> {
            while (!found.get()) {
                // 使用指定字符类型生成随机字符串
                String rnd = generateRandomString(randLen, charType);
                String md5 = computeMD5(rnd);
                if (md5.substring(start, start + target.length()).equals(target)) {
                    if (found.compareAndSet(false, true)) {
                        result.append("找到字符串: ").append(rnd).append(" => ").append(md5);
                    }
                    break;
                }
            }
        };

        for (int i = 0; i < cpus; i++) {
            executor.submit(task);
        }
        executor.shutdown();
        while (!executor.isTerminated()) {
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) { }
        }
        return result.toString();
    }

    /**
     * 双次碰撞：寻找一个随机字符串，使其经过两次 MD5 计算后均满足目标匹配条件
     */
    public String doubleCollision(String target, int start, int randLen, String charType) {
        final AtomicBoolean found = new AtomicBoolean(false);
        final StringBuilder result = new StringBuilder();
        int cpus = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(cpus);

        Runnable task = () -> {
            while (!found.get()) {
                String rnd = generateRandomString(randLen, charType);
                String md5_1 = computeMD5(rnd);
                if (md5_1.substring(start, start + target.length()).equals(target)) {
                    String md5_2 = computeMD5(md5_1);
                    if (md5_2.substring(start, start + target.length()).equals(target)) {
                        if (found.compareAndSet(false, true)) {
                            result.append("找到字符串: ").append(rnd)
                                    .append("\n第一次: ").append(md5_1)
                                    .append("\n第二次: ").append(md5_2);
                        }
                        break;
                    }
                }
            }
        };

        for (int i = 0; i < cpus; i++) {
            executor.submit(task);
        }
        executor.shutdown();
        while (!executor.isTerminated()) {
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) { }
        }
        return result.toString();
    }

    /**
     * 后缀碰撞：在随机字符串后拼接指定后缀后，计算 MD5 并匹配目标
     */
    public String suffixCollision(String target, int start, int randLen, String suffix, String charType) {
        final AtomicBoolean found = new AtomicBoolean(false);
        final StringBuilder result = new StringBuilder();
        int cpus = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(cpus);

        Runnable task = () -> {
            while (!found.get()) {
                String rnd = generateRandomString(randLen, charType);
                String combined = rnd + suffix;
                String md5 = computeMD5(combined);
                if (md5.substring(start, start + target.length()).equals(target)) {
                    if (found.compareAndSet(false, true)) {
                        result.append("找到字符串: ").append(rnd)
                                .append("\n完整字符串: ").append(combined)
                                .append("\nMD5: ").append(md5);
                    }
                    break;
                }
            }
        };

        for (int i = 0; i < cpus; i++) {
            executor.submit(task);
        }
        executor.shutdown();
        while (!executor.isTerminated()) {
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) { }
        }
        return result.toString();
    }

    /**
     * 强碰撞：调用外部 fastcoll 工具生成 MD5 碰撞样本
     * 请确保 fastcoll 工具路径正确，并且工具生成 test_msg1.txt 和 test_msg2.txt 文件
     */
    public String strongCollision(String prefix) {
        File testFile = new File("test.txt");
        try (PrintWriter pw = new PrintWriter(testFile)) {
            pw.print(prefix);
        } catch (FileNotFoundException e) {
            return "写入测试文件失败: " + e.getMessage();
        }
        // 修改 fastcoll 工具路径为实际路径
        String fastcollPath = "D:\\aCTF\\Tool_Web\\fastcoll\\fastcoll_v1.0.0.5.exe";
        ProcessBuilder pb = new ProcessBuilder(fastcollPath, testFile.getAbsolutePath());
        StringBuilder result = new StringBuilder();
        try {
            Process proc = pb.start();
            proc.waitFor();
            String msg1 = readFile("test_msg1.txt");
            String msg2 = readFile("test_msg2.txt");
            result.append("消息1 URL编码: ").append(URLEncoder.encode(msg1, "UTF-8")).append("\n");
            result.append("消息2 URL编码: ").append(URLEncoder.encode(msg2, "UTF-8")).append("\n");
            new File("test_msg1.txt").delete();
            new File("test_msg2.txt").delete();
            testFile.delete();
        } catch (Exception ex) {
            return "fastcoll 执行出错: " + ex.getMessage();
        }
        return result.toString();
    }

    /**
     * 读取文件内容，返回字符串
     */
    private String readFile(String filename) {
        try {
            byte[] data = java.nio.file.Files.readAllBytes(new File(filename).toPath());
            return new String(data);
        } catch (IOException e) {
            return "";
        }
    }
}