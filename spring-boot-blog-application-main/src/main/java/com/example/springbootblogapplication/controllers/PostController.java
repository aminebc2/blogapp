package com.example.springbootblogapplication.controllers;

import com.example.springbootblogapplication.models.Account;
import com.example.springbootblogapplication.models.Post;
import com.example.springbootblogapplication.services.AccountService;
import com.example.springbootblogapplication.services.FileService;
import com.example.springbootblogapplication.services.PostService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.security.Principal;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
@Slf4j
public class PostController {

    private final PostService postService;
    private final AccountService accountService;
    private final FileService fileService;

    @GetMapping("/posts/{id}")
    public String getPost(@PathVariable Long id, Model model) {
        Optional<Post> optionalPost = this.postService.getById(id);
        if (optionalPost.isPresent()) {
            Post post = optionalPost.get();
            model.addAttribute("post", post);
            return "post";
        } else {
            return "404";
        }
    }

    @PostMapping("/posts/{id}")
    @PreAuthorize("isAuthenticated()")
    public String updatePost(@PathVariable Long id, Post post, @RequestParam("file") MultipartFile file, Principal principal) {
        Optional<Post> optionalPost = postService.getById(id);
        if (optionalPost.isPresent()) {
            Post existingPost = optionalPost.get();
            String authUsername = principal != null ? principal.getName() : "anonymousUser";

            if (!existingPost.getAccount().getEmail().equals(authUsername)) {
                return "403"; // Return a 403 Forbidden error page
            }

            existingPost.setTitle(post.getTitle());
            existingPost.setBody(post.getBody());

            try {
                fileService.save(file);
                existingPost.setImageFilePath(file.getOriginalFilename());
            } catch (Exception e) {
                log.error("Error processing file: {}", file.getOriginalFilename());
            }

            postService.save(existingPost);
        }

        return "redirect:/posts/" + post.getId();
    }

    @GetMapping("/posts/new")
    @PreAuthorize("isAuthenticated()")
    public String createNewPost(Model model) {
        Post post = new Post();
        model.addAttribute("post", post);
        return "post_new";
    }

    @PostMapping("/posts/new")
    @PreAuthorize("isAuthenticated()")
    public String createNewPost(@ModelAttribute Post post, @RequestParam("file") MultipartFile file, Principal principal) {
        String authUsername = "anonymousUser";
        if (principal != null) {
            authUsername = principal.getName();
        }

        Account account = accountService.findOneByEmail(authUsername).orElseThrow(() -> new IllegalArgumentException("Account not found"));

        try {
            fileService.save(file);
            post.setImageFilePath(file.getOriginalFilename());
        } catch (Exception e) {
            log.error("Error processing file: {}", file.getOriginalFilename());
        }

        post.setAccount(account);
        postService.save(post);
        return "redirect:/";
    }

    @GetMapping("/posts/{id}/edit")
    @PreAuthorize("isAuthenticated()")
    public String getPostForEdit(@PathVariable Long id, Model model, Principal principal) {
        Optional<Post> optionalPost = postService.getById(id);
        if (optionalPost.isPresent()) {
            Post post = optionalPost.get();
            String authUsername = principal != null ? principal.getName() : "anonymousUser";

            if (!post.getAccount().getEmail().equals(authUsername)) {
                return "403"; // Return a 403 Forbidden error page
            }

            model.addAttribute("post", post);
            return "post_edit";
        } else {
            return "404";
        }
    }

    @GetMapping("/posts/{id}/delete")
    @PreAuthorize("isAuthenticated()")
    public String deletePost(@PathVariable Long id, Principal principal) {
        Optional<Post> optionalPost = postService.getById(id);
        if (optionalPost.isPresent()) {
            Post post = optionalPost.get();
            String authUsername = principal != null ? principal.getName() : "anonymousUser";

            // Check if the authenticated user is either an admin or the owner of the post
            Account account = accountService.findOneByEmail(authUsername).orElseThrow(() -> new IllegalArgumentException("Account not found"));
            boolean isAdmin = account.getAuthorities().stream().anyMatch(authority -> authority.getName().equals("ROLE_ADMIN"));
            boolean isOwner = post.getAccount().getEmail().equals(authUsername);

            if (!isAdmin && !isOwner) {
                return "403"; // Return a 403 Forbidden error page
            }

            postService.delete(post);
            return "redirect:/";
        } else {
            return "404";
        }
    }
}
