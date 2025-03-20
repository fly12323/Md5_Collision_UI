package org.example.md5;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

/**
 * 主程序入口
 * 作用：启动 JavaFX 应用，加载 FXML 布局并显示主界面。
 */
public class App extends Application {
    @Override
    public void start(Stage primaryStage) throws Exception {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/org/example/md5/md5-view.fxml"));
        Scene scene = new Scene(loader.load());
        primaryStage.setTitle("MD5 工具");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
