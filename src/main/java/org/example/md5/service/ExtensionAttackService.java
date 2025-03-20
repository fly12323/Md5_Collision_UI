package org.example.md5.service;

import org.example.md5.utils.Md5ExtensionAttack;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * MD5 长度扩展攻击服务
 * 作用：调用 Md5ExtensionAttack 工具对已知消息进行长度扩展攻击
 */
public class ExtensionAttackService {

    /**
     * 执行 MD5 长度扩展攻击
     * @param messageLen 原始消息长度
     * @param knownHash  已知消息的 MD5 哈希值
     * @param appendText 要追加的字符串
     * @return 攻击结果字符串
     */
    public String attack(int messageLen, String knownHash, String appendText) {
        try {
            Md5ExtensionAttack.Result result = Md5ExtensionAttack.attack(messageLen, knownHash, appendText.getBytes(StandardCharsets.ISO_8859_1));
            String extendText = new String(result.extendText, StandardCharsets.ISO_8859_1);
            StringBuilder sb = new StringBuilder();
            sb.append("Extend text: ").append(extendText).append("\n");
            sb.append("Extend text (URL encoded): ")
                    .append(URLEncoder.encode(extendText, StandardCharsets.ISO_8859_1.name()))
                    .append("\n");
            sb.append("Final hash: ").append(result.finalHash).append("\n");
            return sb.toString();
        } catch (Exception ex) {
            return "攻击出错: " + ex.getMessage();
        }
    }
}