package org.example.md5.controller;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import org.example.md5.service.CollisionService;
import org.example.md5.service.ExtensionAttackService;
import org.example.md5.service.Md5Service;

/**
 * 控制器：处理界面事件
 * 作用：调用各个服务处理 MD5 相关操作（加密、碰撞攻击、长度扩展攻击）
 */
public class Md5Controller {

    // FXML 控件（MD5 加密）
    @FXML private ComboBox<String> inputTypeComboBox;
    @FXML private TextField encryptionInputField;
    @FXML private TextArea encryptionResultArea;

    // FXML 控件（单次 MD5 碰撞）
    @FXML private TextField singleTargetField;
    @FXML private TextField singleStartField;
    @FXML private TextField singleLengthField;
    @FXML private TextArea singleResultArea;

    // FXML 控件（双次 MD5 碰撞）
    @FXML private TextField doubleTargetField;
    @FXML private TextField doubleStartField;
    @FXML private TextField doubleLengthField;
    @FXML private TextArea doubleResultArea;

    // FXML 控件（后缀 MD5 碰撞）
    @FXML private TextField suffixTargetField;
    @FXML private TextField suffixStartField;
    @FXML private TextField suffixLengthField;
    @FXML private TextField suffixField;
    @FXML private TextArea suffixResultArea;

    // FXML 控件（强碰撞）
    @FXML private TextField strongPrefixField;
    @FXML private TextArea strongResultArea;

    // FXML 控件（MD5 长度扩展攻击）
    @FXML private TextField extendMsgLenField;
    @FXML private TextField extendKnownHashField;
    @FXML private TextField extendAppendField;
    @FXML private TextArea extendResultArea;

    // 服务对象
    private Md5Service md5Service = new Md5Service();
    private CollisionService collisionService = new CollisionService();
    private ExtensionAttackService extensionAttackService = new ExtensionAttackService();

    /**
     * 处理 MD5 加密操作
     */
    @FXML
    public void startMd5Encryption() {
        String input = encryptionInputField.getText();
        if (input == null || input.isEmpty()) {
            encryptionResultArea.setText("请输入文本");
            return;
        }
        String type = (inputTypeComboBox.getValue() != null) ? inputTypeComboBox.getValue() : "普通字符";
        String result = md5Service.encrypt(input, type);
        encryptionResultArea.setText(result);
    }

    /**
     * 处理单次 MD5 碰撞攻击
     */
    @FXML
    public void startSingleCollision() {
        String target = singleTargetField.getText().trim();
        int start = singleStartField.getText().isEmpty() ? 0 : Integer.parseInt(singleStartField.getText().trim());
        int randLen = singleLengthField.getText().isEmpty() ? 20 : Integer.parseInt(singleLengthField.getText().trim());
        singleResultArea.clear();

        new Thread(() -> {
            String result = collisionService.singleCollision(target, start, randLen);
            Platform.runLater(() -> singleResultArea.setText(result));
        }).start();
    }

    /**
     * 处理双次 MD5 碰撞攻击
     */
    @FXML
    public void startDoubleCollision() {
        String target = doubleTargetField.getText().trim();
        int start = doubleStartField.getText().isEmpty() ? 0 : Integer.parseInt(doubleStartField.getText().trim());
        int randLen = doubleLengthField.getText().isEmpty() ? 20 : Integer.parseInt(doubleLengthField.getText().trim());
        doubleResultArea.clear();

        new Thread(() -> {
            String result = collisionService.doubleCollision(target, start, randLen);
            Platform.runLater(() -> doubleResultArea.setText(result));
        }).start();
    }

    /**
     * 处理后缀 MD5 碰撞攻击
     */
    @FXML
    public void startSuffixCollision() {
        String target = suffixTargetField.getText().trim();
        int start = suffixStartField.getText().isEmpty() ? 0 : Integer.parseInt(suffixStartField.getText().trim());
        int randLen = suffixLengthField.getText().isEmpty() ? 20 : Integer.parseInt(suffixLengthField.getText().trim());
        String suffix = suffixField.getText().trim();
        suffixResultArea.clear();

        new Thread(() -> {
            String result = collisionService.suffixCollision(target, start, randLen, suffix);
            Platform.runLater(() -> suffixResultArea.setText(result));
        }).start();
    }

    /**
     * 处理强碰撞攻击
     */
    @FXML
    public void startStrongCollision() {
        String prefix = strongPrefixField.getText().trim();
        strongResultArea.clear();

        new Thread(() -> {
            String result = collisionService.strongCollision(prefix);
            Platform.runLater(() -> strongResultArea.setText(result));
        }).start();
    }

    /**
     * 处理 MD5 长度扩展攻击
     */
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
        String result = extensionAttackService.attack(messageLen, knownHash, appendText);
        extendResultArea.setText(result);
    }
}