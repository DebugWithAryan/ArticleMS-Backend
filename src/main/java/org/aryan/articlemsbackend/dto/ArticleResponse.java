package org.aryan.articlemsbackend.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ArticleResponse {
    private Long id;
    private String title;
    private String content;
    private String authorName;
    private Long authorId;
    private String status;
    private Long viewCount;
    private String createdAt;
    private String updatedAt;
}
