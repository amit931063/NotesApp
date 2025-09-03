package com.NotesApp.NotesApp.payloads.response;


import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class TokenRefreshResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType = "Bearer";
}
