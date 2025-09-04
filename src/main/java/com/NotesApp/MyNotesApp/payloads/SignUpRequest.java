package com.NotesApp.NotesApp.payloads;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;

@Data
@Builder
@ToString
public class SignUpRequest {
    @NotBlank
    @Size(min = 3, max = 20)
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

//    private Set<String> role;

    @NotBlank
    @Size(min = 6, max = 40)
    private String password;

//    public Set<String> getRoles() { return role; }
//    public void setRoles(Set<String> role) { this.role = role; }
//

}
