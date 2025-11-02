package org.aryan.articlemsbackend.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.aryan.articlemsbackend.dto.ArticleRequest;
import org.aryan.articlemsbackend.dto.ArticleResponse;
import org.aryan.articlemsbackend.dto.MessageResponse;
import org.aryan.articlemsbackend.service.ArticleService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/articles")
@RequiredArgsConstructor
public class ArticleController {

    private final ArticleService articleService;

    @GetMapping
    public ResponseEntity<Page<ArticleResponse>> getAllArticles(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir) {

        Sort sort = sortDir.equalsIgnoreCase("asc") ?
                Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        Pageable pageable = PageRequest.of(page, size, sort);

        Page<ArticleResponse> articles = articleService.getAllArticles(pageable);
        return ResponseEntity.ok(articles);
    }


    @GetMapping("/search")
    public ResponseEntity<Page<ArticleResponse>> searchArticles(
            @RequestParam String keyword,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, size,
                Sort.by("createdAt").descending());
        Page<ArticleResponse> articles = articleService.searchArticles(keyword, pageable);
        return ResponseEntity.ok(articles);
    }


    @GetMapping("/{id}")
    public ResponseEntity<ArticleResponse> getArticleById(@PathVariable Long id) {
        ArticleResponse article = articleService.getArticleById(id);
        return ResponseEntity.ok(article);
    }


    @GetMapping("/my")
    public ResponseEntity<Page<ArticleResponse>> getMyArticles(
            Authentication authentication,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        String userEmail = authentication.getName();
        Pageable pageable = PageRequest.of(page, size,
                Sort.by("createdAt").descending());
        Page<ArticleResponse> articles = articleService.getMyArticles(userEmail, pageable);
        return ResponseEntity.ok(articles);
    }


    @PostMapping
    public ResponseEntity<ArticleResponse> createArticle(
            @Valid @RequestBody ArticleRequest request,
            Authentication authentication) {

        String userEmail = authentication.getName();
        ArticleResponse article = articleService.createArticle(request, userEmail);
        return ResponseEntity.status(HttpStatus.CREATED).body(article);
    }


    @PutMapping("/{id}")
    public ResponseEntity<ArticleResponse> updateArticle(
            @PathVariable Long id,
            @Valid @RequestBody ArticleRequest request,
            Authentication authentication) {

        String userEmail = authentication.getName();
        ArticleResponse article = articleService.updateArticle(id, request, userEmail);
        return ResponseEntity.ok(article);
    }


    @DeleteMapping("/{id}")
    public ResponseEntity<MessageResponse> deleteArticle(
            @PathVariable Long id,
            Authentication authentication) {

        String userEmail = authentication.getName();
        articleService.deleteArticle(id, userEmail);
        return ResponseEntity.ok(new MessageResponse("Article deleted successfully"));
    }
}
