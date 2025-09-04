package com.NotesApp.NotesApp.payloads.response;

import lombok.Data;

import java.time.LocalDateTime;


@Data
public class NotificationDto {
    private String message;
    private String type;
    private String priority;
    private boolean read;
    private LocalDateTime timestamp;
}
