package com.NotesApp.NotesApp.controllers;


import com.NotesApp.NotesApp.models.Note;
import com.NotesApp.NotesApp.models.User;
import com.NotesApp.NotesApp.repositories.NoteRepository;
import com.NotesApp.NotesApp.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/notes")
public class NoteController {


    @Autowired
    NoteRepository noteRepository;
    @Autowired
    UserRepository userRepository;


//    private User getCurrentUser() {
//        String email = SecurityContextHolder.getContext().getAuthentication().getName();
//        return userRepo.findByEmail(email).orElseThrow();
//    }
//
//
//    @GetMapping
//    public List<Note> list() {
//        return noteRepo.findAllByUserId(getCurrentUser().getId());
//    }
//
//
//    @PostMapping
//    public Note create(@RequestBody Note n) {
//        n.setUser(getCurrentUser());
//        n.setCreatedAt(Instant.now());
//        n.setUpdatedAt(Instant.now());
//        return noteRepo.save(n);
//    }
//
//
//    @GetMapping("/{id}")
//    public ResponseEntity<Note> get(@PathVariable Long id) {
//        Note note = noteRepo.findById(id).orElseThrow();
//        if (!note.getUser().getId().equals(getCurrentUser().getId())) return ResponseEntity.status(403).build();
//        return ResponseEntity.ok(note);
//    }
//
//
//    @PutMapping("/{id}")
//    public ResponseEntity<Note> update(@PathVariable Long id, @RequestBody Note data) {
//        Note note = noteRepo.findById(id).orElseThrow();
//        if (!note.getUser().getId().equals(getCurrentUser().getId())) return ResponseEntity.status(403).build();
//        note.setTitle(data.getTitle());
//        note.setContent(data.getContent());
//        note.setUpdatedAt(Instant.now());
//        return ResponseEntity.ok(noteRepo.save(note));
//    }
//
//
//    @DeleteMapping("/{id}")
//    public ResponseEntity<?> delete(@PathVariable Long id) {
//        Note note = noteRepo.findById(id).orElseThrow();
//        if (!note.getUser().getId().equals(getCurrentUser().getId())) return ResponseEntity.status(403).build();
//        noteRepo.delete(note);
//        return ResponseEntity.ok().build();
//    }

    private User getCurrentUser() {
//        String email = SecurityContextHolder.getContext().getAuthentication().getName();
//        return userRepo.findByEmail(email)
//                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String loginInput = authentication.getName();  // This might be username or email

        return userRepository.findByUsername(loginInput)
                .or(() -> userRepository.findByEmail(loginInput)) // check both
                .orElseThrow(() -> new RuntimeException("User not found with username/email: " + loginInput));

    }

    @GetMapping
    public List<Note> list() {
        return noteRepository.findAllByUserId(getCurrentUser().getId());
    }

    @PostMapping
    public ResponseEntity<Note> create(@RequestBody Note note) {
        note.setUser(getCurrentUser());
        note.setCreatedAt(Instant.now());
        note.setUpdatedAt(Instant.now());
        note.setShareId(UUID.randomUUID().toString());
        note.setSharedAt(Instant.now());
        Note saved = noteRepository.save(note);
        return ResponseEntity.ok(saved);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Note> get(@PathVariable Long id) {
        Note note = noteRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Note not found with id: " + id));
        if (!note.getUser().getId().equals(getCurrentUser().getId())) {
            return ResponseEntity.status(403).build();
        }
        return ResponseEntity.ok(note);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Note> update(@PathVariable Long id, @RequestBody Note data) {
        Note note = noteRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Note not found with id: " + id));
        if (!note.getUser().getId().equals(getCurrentUser().getId())) {
            return ResponseEntity.status(403).build();
        }
        note.setTitle(data.getTitle());
        note.setContent(data.getContent());
        note.setUpdatedAt(Instant.now());
        return ResponseEntity.ok(noteRepository.save(note));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        Note note = noteRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Note not found with id: " + id));
        if (!note.getUser().getId().equals(getCurrentUser().getId())) {
            return ResponseEntity.status(403).build();
        }
        noteRepository.delete(note);
        return ResponseEntity.ok().build();
    }

    // ✅ Generate a public shareable link for a note
    @PostMapping("/{id}/share")
    public ResponseEntity<?> shareNote(@PathVariable Long id) {
        Note note = noteRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Note not found"));

        if (note.getPublicId() == null) {
            note.setPublicId(UUID.randomUUID().toString());  // generate unique share ID
            note.setShared(true);                           // mark note as shared
            noteRepository.save(note);
        }

        String shareUrl = "https://your-frontend.vercel.app/n/" + note.getPublicId();
        return ResponseEntity.ok(Map.of("shareUrl", shareUrl));
    }


    // ✅ Fetch a shared note by publicId (for frontend sharing)
    @GetMapping("/public/{publicId}")
    public ResponseEntity<?> getSharedNote(@PathVariable String publicId) {
        Note note = noteRepository.findByPublicId(publicId)
                .orElseThrow(() -> new RuntimeException("Shared note not found"));

        return ResponseEntity.ok(note);
    }


}
