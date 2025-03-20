package org.example.md5.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * 自定义 MD5 实现
 * 作用：提供自定义的 MD5 算法实现，支持扩展攻击
 */
public class CustomMD5 {
    public int A, B, C, D;
    private final int[] r = {
            7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
            5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
            4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
            6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    };
    private final int[] k = new int[64];

    public CustomMD5() {
        // 初始化 MD5 状态
        A = 0x67452301;
        B = 0xefcdab89;
        C = 0x98badcfe;
        D = 0x10325476;
        for (int i = 0; i < 64; i++) {
            k[i] = (int)(((long) Math.floor(Math.abs(Math.sin(i + 1)) * (1L << 32))) & 0xffffffffL);
        }
    }

    private int leftRotate(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    /**
     * 处理 64 字节数据块
     */
    public void update(byte[] chunk) {
        int[] w = new int[16];
        ByteBuffer buffer = ByteBuffer.wrap(chunk);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < 16; i++) {
            w[i] = buffer.getInt();
        }
        int a = A, b = B, c = C, d = D;
        for (int i = 0; i < 64; i++) {
            int f, g;
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (b & d) | (c & (~d));
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }
            int temp = d;
            d = c;
            c = b;
            b = b + leftRotate(a + f + k[i] + w[g], r[i]);
            a = temp;
        }
        A += a;
        B += b;
        C += c;
        D += d;
    }

    /**
     * 对消息进行扩展（必须是 64 字节的倍数）
     */
    public void extend(byte[] msg) {
        for (int i = 0; i < msg.length; i += 64) {
            byte[] chunk = Arrays.copyOfRange(msg, i, i + 64);
            update(chunk);
        }
    }

    /**
     * 对消息进行填充
     */
    public byte[] padding(byte[] msg) {
        int originalLength = msg.length;
        long bitLength = originalLength * 8L;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            bos.write(msg);
            bos.write(0x80);
            int padLen = (56 - (originalLength + 1) % 64 + 64) % 64;
            for (int i = 0; i < padLen; i++) {
                bos.write(0);
            }
            ByteBuffer lenBuffer = ByteBuffer.allocate(8);
            lenBuffer.order(ByteOrder.LITTLE_ENDIAN);
            lenBuffer.putLong(bitLength);
            bos.write(lenBuffer.array());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bos.toByteArray();
    }

    /**
     * 获取当前 MD5 计算结果
     */
    public byte[] digest() {
        ByteBuffer buffer = ByteBuffer.allocate(16);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(A);
        buffer.putInt(B);
        buffer.putInt(C);
        buffer.putInt(D);
        return buffer.array();
    }
}