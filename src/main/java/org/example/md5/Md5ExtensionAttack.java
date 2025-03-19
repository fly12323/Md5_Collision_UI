package org.example.md5;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class Md5ExtensionAttack {

    public static class Result {
        public byte[] extendText;
        public String finalHash;
        public Result(byte[] extendText, String finalHash) {
            this.extendText = extendText;
            this.finalHash = finalHash;
        }
    }

    // 简化实现：使用自定义 MD5 计算，模拟对“已知消息”进行扩展攻击
    public static Result attack(int messageLen, String knownHash, byte[] appendStr) {
        CustomMD5 md5 = new CustomMD5();
        // 构造占位消息（用 '*' 填充）
        byte[] dummy = new byte[messageLen];
        Arrays.fill(dummy, (byte)'*');
        byte[] previousPadding = md5.padding(dummy);
        // 拼接追加字符串
        byte[] currentText = new byte[previousPadding.length + appendStr.length];
        System.arraycopy(previousPadding, 0, currentText, 0, previousPadding.length);
        System.arraycopy(appendStr, 0, currentText, previousPadding.length, appendStr.length);

        // 设置 MD5 状态为已知哈希（将 32 位十六进制转为 4 个 int，注意字节序）
        ByteBuffer bb = ByteBuffer.wrap(hexStringToByteArray(knownHash));
        bb.order(ByteOrder.LITTLE_ENDIAN);
        md5.A = bb.getInt();
        md5.B = bb.getInt();
        md5.C = bb.getInt();
        md5.D = bb.getInt();

        // 只对追加部分进行扩展：跳过 previousPadding 部分
        byte[] toExtend = md5.padding(currentText);
        byte[] extendPart = Arrays.copyOfRange(toExtend, previousPadding.length, toExtend.length);
        md5.extend(extendPart);
        byte[] finalDigest = md5.digest();
        return new Result(Arrays.copyOfRange(currentText, messageLen, currentText.length), bytesToHex(finalDigest));
    }

    // 辅助方法：16 进制字符串转字节数组
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    // 辅助方法：字节数组转 16 进制字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes){
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
