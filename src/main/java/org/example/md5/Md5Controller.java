package org.example.md5;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;

import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class Md5Controller {

    // MD5 加密页控件
    @FXML private ComboBox<String> inputTypeComboBox;
    @FXML private TextField encryptionInputField;
    @FXML private TextArea encryptionResultArea;

    // 单次 MD5 碰撞 UI
    @FXML private TextField singleTargetField;
    @FXML private TextField singleStartField;
    @FXML private TextField singleLengthField;
    @FXML private TextArea singleResultArea;

    // 双次 MD5 碰撞 UI
    @FXML private TextField doubleTargetField;
    @FXML private TextField doubleStartField;
    @FXML private TextField doubleLengthField;
    @FXML private TextArea doubleResultArea;

    // 后缀 MD5 碰撞 UI
    @FXML private TextField suffixTargetField;
    @FXML private TextField suffixStartField;
    @FXML private TextField suffixLengthField;
    @FXML private TextField suffixField;
    @FXML private TextArea suffixResultArea;

    // 强碰撞 UI
    @FXML private TextField strongPrefixField;
    @FXML private TextArea strongResultArea;

    // MD5 长度扩展攻击 UI
    @FXML private TextField extendMsgLenField;
    @FXML private TextField extendKnownHashField;
    @FXML private TextField extendAppendField;
    @FXML private TextArea extendResultArea;

    // 用于随机字符生成
    private static final String CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private String generateRandomString(int len) {
        Random rand = new Random();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(CHARS.charAt(rand.nextInt(CHARS.length())));
        }
        return sb.toString();
    }

    // 修改后的计算MD5方法（移除内部解码，支持指定字符集）
    private String computeMD5(String input, Charset charset) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(charset));
            StringBuilder hexString = new StringBuilder();
            for (byte b : digest) {
                hexString.append(String.format("%02x", b & 0xFF)); // 修复符号扩展问题
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException ex) {
            return "MD5 算法不可用: " + ex.getMessage();
        }
    }

    // 修改后的MD5加密核心逻辑
    @FXML
    public void startMd5Encryption() {
        String input = encryptionInputField.getText();
        if (input == null || input.isEmpty()) {
            encryptionResultArea.setText("请输入文本");
            return;
        }

        String type = inputTypeComboBox.getValue() != null ?
                inputTypeComboBox.getValue() : "普通字符";

        try {
            String processedInput = input;
            Charset processingCharset = StandardCharsets.UTF_8;

            // URL类型特殊处理
            if ("URL".equals(type)) {
                // 关键修改：使用ISO-8859-1解码保留原始字节
                processedInput = URLDecoder.decode(input, StandardCharsets.ISO_8859_1.name());
                processingCharset = StandardCharsets.ISO_8859_1;
            }

            // 计算MD5（根据类型选择字符集）
            String hash = computeMD5(processedInput, processingCharset);

            // 构建结果输出
            StringBuilder result = new StringBuilder();
            result.append("输入类型: ").append(type).append("\n");
            if ("URL".equals(type)) {
                result.append("URL解码后原始数据: ")
                        .append(processedInput) // 注意：可能包含不可打印字符
                        .append("\n");
            }
            result.append("MD5: ").append(hash);
            encryptionResultArea.setText(result.toString());
        } catch (Exception e) {
            encryptionResultArea.setText("错误: " + e.getMessage());
        }
    }


    // 单次碰撞：计算 MD5 后，比较其指定位置的子串是否匹配目标
    @FXML
    public void startSingleCollision() {
        String target = singleTargetField.getText().trim();
        int start = singleStartField.getText().isEmpty() ? 0 : Integer.parseInt(singleStartField.getText().trim());
        int randLen = suffixLengthField.getText().isEmpty() ? 20 : Integer.parseInt(singleLengthField.getText().trim());
        final AtomicBoolean found = new AtomicBoolean(false);
        singleResultArea.clear();

        int cpus = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(cpus);

        Runnable task = () -> {
            while (!found.get()) {
                String rnd = generateRandomString(randLen);
                String md5 = computeMD5(rnd, StandardCharsets.UTF_8);
                if (md5.substring(start, start + target.length()).equals(target)) {
                    if (found.compareAndSet(false, true)) {
                        Platform.runLater(() -> singleResultArea.setText("找到字符串: " + rnd + " => " + md5));
                    }
                    break;
                }
            }
        };

        for (int i = 0; i < cpus; i++) {
            executor.submit(task);
        }
        executor.shutdown();
    }

    // 双次碰撞：第一次 MD5 碰撞后，再对结果进行 MD5 检查
    @FXML
    public void startDoubleCollision() {
        String target = doubleTargetField.getText().trim();
        int start = doubleStartField.getText().isEmpty() ? 0 : Integer.parseInt(doubleStartField.getText().trim());
        int randLen = doubleLengthField.getText().isEmpty() ? 20 : Integer.parseInt(doubleLengthField.getText().trim());
        final AtomicBoolean found = new AtomicBoolean(false);
        doubleResultArea.clear();

        int cpus = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(cpus);

        Runnable task = () -> {
            while (!found.get()) {
                String rnd = generateRandomString(randLen);
                String md5_1 = computeMD5(rnd, StandardCharsets.UTF_8);
                if (md5_1.substring(start, start + target.length()).equals(target)) {
                    String md5_2 = computeMD5(md5_1, StandardCharsets.UTF_8);
                    if (md5_2.substring(start, start + target.length()).equals(target)) {
                        if (found.compareAndSet(false, true)) {
                            Platform.runLater(() -> doubleResultArea.setText("找到字符串: " + rnd + "\n第一次: " + md5_1 + "\n第二次: " + md5_2));
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
    }

    // 后缀碰撞：在随机字符串后拼接指定后缀，再计算 MD5
    @FXML
    public void startSuffixCollision() {
        String target = suffixTargetField.getText().trim();
        int start = suffixStartField.getText().isEmpty() ? 0 : Integer.parseInt(suffixStartField.getText().trim());
        int randLen = suffixLengthField.getText().isEmpty() ? 20 : Integer.parseInt(suffixLengthField.getText().trim());
        String suffix = suffixField.getText().trim();
        final AtomicBoolean found = new AtomicBoolean(false);
        suffixResultArea.clear();

        int cpus = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(cpus);

        Runnable task = () -> {
            while (!found.get()) {
                String rnd = generateRandomString(randLen);
                String combined = rnd + suffix;
                String md5 = computeMD5(combined, StandardCharsets.UTF_8);
                if (md5.substring(start, start + target.length()).equals(target)) {
                    if (found.compareAndSet(false, true)) {
                        Platform.runLater(() -> suffixResultArea.setText("找到字符串: " + rnd + "\n完整字符串: " + combined + "\nMD5: " + md5));
                    }
                    break;
                }
            }
        };

        for (int i = 0; i < cpus; i++) {
            executor.submit(task);
        }
        executor.shutdown();
    }

    // 强碰撞：调用外部 fastcoll 工具（请根据实际情况修改工具路径）
    @FXML
    public void startStrongCollision() {
        String prefix = strongPrefixField.getText().trim();
        strongResultArea.clear();
        // 生成测试文件
        File testFile = new File("test.txt");
        try (PrintWriter pw = new PrintWriter(testFile)) {
            pw.print(prefix);
        } catch (FileNotFoundException e) {
            strongResultArea.setText("写入测试文件失败: " + e.getMessage());
            return;
        }
        // fastcoll 工具路径（请修改为实际路径）
        String fastcollPath = "D:\\aCTF\\Tool_Web\\fastcoll\\fastcoll_v1.0.0.5.exe";
        ProcessBuilder pb = new ProcessBuilder(fastcollPath, testFile.getAbsolutePath());
        try {
            Process proc = pb.start();
            proc.waitFor();
            // 假设 fastcoll 生成 test_msg1.txt 和 test_msg2.txt
            String msg1 = readFileBytes("test_msg1.txt");
            String msg2 = readFileBytes("test_msg2.txt");
            StringBuilder sb = new StringBuilder();
            sb.append("消息1 URL编码: ").append(java.net.URLEncoder.encode(msg1, "UTF-8")).append("\n");
            sb.append("消息2 URL编码: ").append(java.net.URLEncoder.encode(msg2, "UTF-8")).append("\n");
            Platform.runLater(() -> strongResultArea.setText(sb.toString()));
            // 清理临时文件
            new File("test_msg1.txt").delete();
            new File("test_msg2.txt").delete();
            testFile.delete();
        } catch (Exception ex) {
            Platform.runLater(() -> strongResultArea.setText("fastcoll 执行出错: " + ex.getMessage()));
        }
    }

    private String readFileBytes(String filename) {
        try {
            byte[] data = java.nio.file.Files.readAllBytes(new File(filename).toPath());
            return new String(data);
        } catch (IOException e) {
            return "";
        }
    }

    // MD5 长度扩展攻击（简化示例）
    @FXML
    public void startMd5ExtensionAttack() {
        String msgLenStr = extendMsgLenField.getText().trim();
        String knownHash = extendKnownHashField.getText().trim();
        String appendText = extendAppendField.getText().trim();
        extendResultArea.clear();
        if (msgLenStr.isEmpty() || knownHash.isEmpty() || appendText.isEmpty()) {
            extendResultArea.setText("请填写所有参数");
            return;
        }
        int messageLen = Integer.parseInt(msgLenStr);
        // 调用 MD5 扩展攻击（使用自定义实现）
        try {
            Md5ExtensionAttack.Result result = Md5ExtensionAttack.attack(messageLen, knownHash, appendText.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            sb.append("Extend text: ").append(new String(result.extendText, "UTF-8")).append("\n");
            sb.append("Extend text (URL encoded): ").append(java.net.URLEncoder.encode(new String(result.extendText, "UTF-8"), "UTF-8")).append("\n");
            sb.append("Final hash: ").append(result.finalHash).append("\n");
            extendResultArea.setText(sb.toString());
        } catch (Exception ex) {
            extendResultArea.setText("攻击出错: " + ex.getMessage());
        }
    }
}
