package org.aryan.articlemsbackend.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aryan.articlemsbackend.dto.ArticleRequest;
import org.aryan.articlemsbackend.dto.ArticleResponse;
import org.aryan.articlemsbackend.entity.Article;
import org.aryan.articlemsbackend.entity.User;
import org.aryan.articlemsbackend.exception.ForbiddenException;
import org.aryan.articlemsbackend.exception.ResourceNotFoundException;
import org.aryan.articlemsbackend.repo.ArticleRepository;
import org.aryan.articlemsbackend.repo.UserRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.format.DateTimeFormatter;

@Service
@RequiredArgsConstructor
@Slf4j
public class ArticleService {

    private final ArticleRepository articleRepository;
    private final UserRepository userRepository;
    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");


    @Transactional(readOnly = true)
    public Page<ArticleResponse> getAllArticles(Pageable pageable) {
        log.info("Fetching all articles - page: {}, size: {}",
                pageable.getPageNumber(), pageable.getPageSize());

        return articleRepository.findAll(pageable)
                .map(this::mapToResponse);
    }

    @Transactional(readOnly = true)
    public Page<ArticleResponse> searchArticles(String keyword, Pageable pageable) {
        log.info("Searching articles with keyword: {}", keyword);

        return articleRepository.searchArticles(keyword, pageable)
                .map(this::mapToResponse);
    }


    @Transactional
    public ArticleResponse getArticleById(Long id) {
        log.info("Fetching article with ID: {}", id);

        Article article = articleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Article not found with id: " + id));

        // Increment view count
        article.incrementViewCount();
        articleRepository.save(article);

        return mapToResponse(article);
    }


    @Transactional(readOnly = true)
    public Page<ArticleResponse> getMyArticles(String userEmail, Pageable pageable) {
        log.info("Fetching articles for user: {}", userEmail);

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Page<Article> articles = articleRepository.findAll(pageable);
        return articles
                .filter(article -> article.getAuthor().getId().equals(user.getId()))
                .map(this::mapToResponse);
    }


    @Transactional
    public ArticleResponse createArticle(ArticleRequest request, String userEmail) {
        log.info("Creating new article for user: {}", userEmail);

        User author = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Article article = Article.builder()
                .title(request.getTitle())
                .content(request.getContent())
                .author(author)
                .authorName(author.getName())
                .build();

        Article savedArticle = articleRepository.save(article);
        log.info("Article created successfully with ID: {}", savedArticle.getId());

        return mapToResponse(savedArticle);
    }


    @Transactional
    public ArticleResponse updateArticle(Long id, ArticleRequest request, String userEmail) {
        log.info("Updating article with ID: {} by user: {}", id, userEmail);

        Article article = articleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Article not found with id: " + id));

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (!article.getAuthor().getId().equals(user.getId())) {
            log.warn("User {} attempted to update article {} without permission",
                    userEmail, id);
            throw new ForbiddenException("You don't have permission to update this article");
        }

        article.setTitle(request.getTitle());
        article.setContent(request.getContent());

        Article updatedArticle = articleRepository.save(article);
        log.info("Article updated successfully: {}", id);

        return mapToResponse(updatedArticle);
    }

    /**
     * Delete article
     */
    @Transactional
    public void deleteArticle(Long id, String userEmail) {
        log.info("Deleting article with ID: {} by user: {}", id, userEmail);

        Article article = articleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Article not found with id: " + id));

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Check if user is the author
        if (!article.getAuthor().getId().equals(user.getId())) {
            log.warn("User {} attempted to delete article {} without permission",
                    userEmail, id);
            throw new ForbiddenException("You don't have permission to delete this article");
        }

        articleRepository.delete(article);
        log.info("Article deleted successfully: {}", id);
    }


    private ArticleResponse mapToResponse(Article article) {
        return ArticleResponse.builder()
                .id(article.getId())
                .title(article.getTitle())
                .content(article.getContent())
                .authorName(article.getAuthorName())
                .authorId(article.getAuthor().getId())
                .status(article.getStatus().name())
                .viewCount(article.getViewCount())
                .createdAt(article.getCreatedAt().format(DATE_FORMATTER))
                .updatedAt(article.getUpdatedAt() != null ?
                        article.getUpdatedAt().format(DATE_FORMATTER) : null)
                .build();
    }
}
