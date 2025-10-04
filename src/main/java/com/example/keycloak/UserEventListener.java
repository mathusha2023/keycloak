package com.example.keycloak;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.RealmModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class UserEventListener implements EventListenerProvider {

    private final String userRegisterUrl;
    private final String backendApiKey;
    private final KeycloakSession session;
    private static final Logger logger = LoggerFactory.getLogger(UserEventListener.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    public UserEventListener(KeycloakSession session) {
        this.session = session;
        this.userRegisterUrl = loadUserRegisterUrlFromEnv();
        this.backendApiKey = loadBackendApiKeyFromEnv();
        logger.info("UserEventListener initialized with URL: {}", userRegisterUrl);
    }

    @Override
    public void onEvent(Event event) {
        if (event.getType().equals(EventType.REGISTER)) {
            System.out.println("Event type: " + event.getType());
            RealmModel realm = session.getContext().getRealm();
            UserModel user = session.users().getUserById(realm, event.getUserId());
            
            if (user != null) {
                Map<String, String> userData = new HashMap<>();
                userData.put("id", user.getId());
                userData.put("first_name", user.getFirstName());
                userData.put("last_name", user.getLastName());
                userData.put("username", user.getUsername());
                userData.put("email", user.getEmail());
                logger.info("Registering user: {}", user.getUsername());
                sendPostRequest(userRegisterUrl, userData);
            } else {
                logger.warn("User not found for event with userId: {}", event.getUserId());
            }
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {}

    private String loadUserRegisterUrlFromEnv() {
        String url = null;
        
        try {
            // Способ 1: Чтение из системных переменных окружения
            url = System.getenv("USER_REGISTER_URL");
            
            // Способ 2: Если не найдено в env, читаем из .env файла
            if (url == null || url.trim().isEmpty()) {
                url = loadFromEnvFile("USER_REGISTER_URL");
            }
            
            // Способ 3: Значение по умолчанию
            if (url == null || url.trim().isEmpty()) {
                url = "http://host.docker.internal:8000/api/users/register";
                logger.warn("USER_REGISTER_URL not found in environment variables or .env file. Using default: {}", url);
            }
            
        } catch (Exception e) {
            logger.error("Error loading USER_REGISTER_URL from environment", e);
            url = "http://host.docker.internal:8000/api/users/register";
        }
        
        return url;
    }

    private String loadBackendApiKeyFromEnv() {
        String apiKey = null;
        
        try {
            // Способ 1: Чтение из системных переменных окружения
            apiKey = System.getenv("BACKEND_API_KEY");
            
            // Способ 2: Если не найдено в env, читаем из .env файла
            if (apiKey == null || apiKey.trim().isEmpty()) {
                apiKey = loadFromEnvFile("BACKEND_API_KEY");
            }
            
            // Способ 3: Ошибка, если токен не найден
            if (apiKey == null || apiKey.trim().isEmpty()) {
                logger.error("BACKEND_API_KEY not found in environment variables or .env file. API key is required for authentication.");
                throw new RuntimeException("BACKEND_API_KEY is required but not found in environment");
            }
            
            logger.info("Backend API key loaded successfully");
            
        } catch (Exception e) {
            logger.error("Error loading BACKEND_API_KEY from environment", e);
            throw new RuntimeException("Failed to load BACKEND_API_KEY", e);
        }
        
        return apiKey;
    }

    private String loadFromEnvFile(String key) {
        try {
            // Пробуем разные возможные пути к .env файлу
            String[] possiblePaths = {
                ".env",
                "/opt/keycloak/.env",
                "/config/.env",
                System.getProperty("user.dir") + "/.env"
            };
            
            for (String path : possiblePaths) {
                if (Files.exists(Paths.get(path))) {
                    Properties props = new Properties();
                    props.load(Files.newInputStream(Paths.get(path)));
                    String value = props.getProperty(key);
                    if (value != null && !value.trim().isEmpty()) {
                        logger.info("Loaded {} from .env file: {}", key, path);
                        return value.trim();
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("Could not load .env file: {}", e.getMessage());
        }
        
        return null;
    }

    private void sendPostRequest(String url, Map<String, String> data) {
        if (url == null || url.trim().isEmpty()) {
            logger.error("Cannot send POST request: URL is null or empty");
            return;
        }
        
        if (backendApiKey == null || backendApiKey.trim().isEmpty()) {
            logger.error("Cannot send POST request: BACKEND_API_KEY is not configured");
            return;
        }
        
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpPost post = new HttpPost(url);
            String json = objectMapper.writeValueAsString(data);
            StringEntity entity = new StringEntity(json, "UTF-8");
            post.setEntity(entity);
            post.setHeader("Accept", "application/json");
            post.setHeader("Content-type", "application/json; charset=UTF-8");
            post.setHeader("X-Secret-Token", backendApiKey); // Добавляем секретный токен
            
            logger.debug("Sending POST request to {} with headers: {}", url, post.getAllHeaders());
            
            HttpResponse response = client.execute(post);
            int statusCode = response.getStatusLine().getStatusCode();
            String responseBody = response.getEntity() != null ? 
                EntityUtils.toString(response.getEntity(), "UTF-8") : "No content";
                
            if (statusCode >= 200 && statusCode < 300) {
                logger.info("POST request to {} completed successfully with status code: {}", url, statusCode);
            } else {
                logger.warn("POST request to {} completed with status code: {} and response: {}", 
                    url, statusCode, responseBody);
            }
        } catch (IOException e) {
            logger.error("Error sending POST request to {}", url, e);
        }
    }

    @Override
    public void close() {
        // Очистка ресурсов, если необходимо
    }
}