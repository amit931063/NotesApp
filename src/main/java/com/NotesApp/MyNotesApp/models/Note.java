package com.NotesApp.NotesApp.models;

import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

@Entity
@Table(name = "notes")
@Data
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Note {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
      @JsonIgnore
    private User user;
    @Column(columnDefinition = "text")
    private String title;
    @Column(columnDefinition = "text")
    private String content;
    private Instant createdAt = Instant.now();
    private Instant updatedAt = Instant.now();
    @Column(unique = true)
    private String shareId; // uuid
    private Instant sharedAt;

    @Column(unique = true)
    private String publicId;

//    private boolean shared;

@Column(nullable = false, columnDefinition = "boolean default false")
private boolean shared = false;






}
