package com.NotesApp.NotesApp.payloads.request;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class TokenRefreshRequest {


    private String refreshToken;

}
