package com.example.auth.messaging;

import com.example.auth.entity.User;

import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class AmqpEventPublisher {

    private final AmqpTemplate amqpTemplate;
    private final String exchange;
    private final String routingKey;

    public AmqpEventPublisher(AmqpTemplate amqpTemplate,
                              @Value("${app.rabbitmq.exchange:user.exchange}") String exchange,
                              @Value("${app.rabbitmq.routing-key:user.registered}") String routingKey) {
        this.amqpTemplate = amqpTemplate;
        this.exchange = exchange;
        this.routingKey = routingKey;
    }

    public void publishUserRegistered(User user, String token) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("userId", user.getId());
        payload.put("email", user.getEmail());
        payload.put("token", token);
        amqpTemplate.convertAndSend(exchange, routingKey, payload);
    }
}
