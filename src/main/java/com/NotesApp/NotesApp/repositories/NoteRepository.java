package com.NotesApp.NotesApp.repositories;


import com.NotesApp.NotesApp.models.Note;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;


@Repository

public interface NoteRepository extends JpaRepository<Note, Long >{
     List<Note> findAllByUserId(Long userId);
Optional<Note> findByShareId(String shareId);
Optional<Note> findByPublicId(String publicId);

}
