package com.NotesApp.NotesApp.payloads;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class TokenRefreshRequest {


    private String refreshToken;

}
