package za.co.webscanner;

import io.javalin.Javalin;
import java.util.Map;

public class App {
    public static void main(String[] args){
        Javalin app = Javalin.create();
        app.get("/health", ctx -> ctx.json(Map.of("status", "ok")));

        app.start(7070);
    }
}