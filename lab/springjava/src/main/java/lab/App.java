package lab;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

import java.util.Map;

@SpringBootApplication
@RestController
public class App {

    private static final Logger log = LogManager.getLogger(App.class);

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }

    @GetMapping("/api/log")
    public Mono<Map<String, String>> logEndpoint(
            @RequestHeader(value = "X-Api-Version", required = false) String version) {
        log.info("request X-Api-Version={}", version);
        return Mono.just(Map.of("logged", String.valueOf(version)));
    }

    @GetMapping("/api/health")
    public Mono<Map<String, String>> health() {
        return Mono.just(Map.of("ok", "true"));
    }
}
