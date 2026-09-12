package burp;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * HunterAI Burp Extender
 * Forwards live proxy HTTP traffic to HunterAI Burp Agent at http://127.0.0.1:8085/api/traffic
 */
public class BurpExtender implements IBurpExtender, IHttpListener {
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private final ExecutorService executor = Executors.newFixedThreadPool(4);
    private final String AGENT_URL = "http://127.0.0.1:8085/api/traffic";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("HunterAI Burp Agent Forwarder");
        callbacks.registerHttpListener(this);
        callbacks.printOutput("[✓] HunterAI Burp Extender Active -> Streaming to " + AGENT_URL);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // Only forward responses (which contain both full request and response)
        if (!messageIsRequest && messageInfo.getResponse() != null) {
            final byte[] requestBytes = messageInfo.getRequest();
            final byte[] responseBytes = messageInfo.getResponse();
            final IHttpService service = messageInfo.getHttpService();

            executor.submit(() -> {
                try {
                    String reqStr = helpers.bytesToString(requestBytes);
                    String respStr = helpers.bytesToString(responseBytes);

                    // Build JSON payload
                    StringBuilder json = new StringBuilder("{");
                    json.append("\"host\":\"").append(escapeJson(service.getHost())).append("\",");
                    json.append("\"port\":").append(service.getPort()).append(",");
                    json.append("\"protocol\":\"").append(service.getProtocol()).append("\",");
                    json.append("\"request\":\"").append(escapeJson(reqStr)).append("\",");
                    json.append("\"response\":\"").append(escapeJson(respStr)).append("\"");
                    json.append("}");

                    sendToAgent(json.toString());
                } catch (Exception e) {
                    callbacks.printError("Forwarding error: " + e.getMessage());
                }
            });
        }
    }

    private void sendToAgent(String jsonPayload) {
        try {
            URL url = new URL(AGENT_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; utf-8");
            conn.setDoOutput(true);
            conn.setConnectTimeout(1500);
            conn.setReadTimeout(1500);

            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonPayload.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }
            conn.getResponseCode();
            conn.disconnect();
        } catch (Exception ignored) {
            // Non-blocking fail-safe if agent is temporarily offline
        }
    }

    private String escapeJson(String raw) {
        if (raw == null) return "";
        return raw.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\b", "\\b")
                  .replace("\f", "\\f")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }
}
