package org.example.md5;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class Md5Application extends Application {
    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(Md5Application.class.getResource("md5-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 1024, 640);
        stage.setTitle("MD5_Collision");
        stage.setScene(scene);
        stage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}
