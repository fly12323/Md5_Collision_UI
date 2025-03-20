module org.example.md5 {
    requires javafx.controls;
    requires javafx.fxml;


    opens org.example.md5.controller to javafx.fxml;
    exports org.example.md5;
}