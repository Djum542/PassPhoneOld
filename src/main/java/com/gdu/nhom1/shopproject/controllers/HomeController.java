package com.gdu.nhom1.shopproject.controllers;

import java.util.List;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

import com.gdu.nhom1.shopproject.models.Product;
import com.gdu.nhom1.shopproject.models.User;
import com.gdu.nhom1.shopproject.services.CategoryService;
import com.gdu.nhom1.shopproject.services.ProductService;
import com.gdu.nhom1.shopproject.services.UserService;

@Controller
public class HomeController {
    @Autowired
    CategoryService categoryService;
    @Autowired
    ProductService productService;

    @Autowired
    UserService userService;

    @GetMapping({ "/", "/home" })
    public String home(Model model, HttpSession session, Authentication authentication) {
        session.setAttribute("session", session);
        String email = "";
        try {
            Object principal = authentication.getPrincipal();
            if (authentication != null) {
            }
            if (principal instanceof UserDetails) {
                email = ((UserDetails) principal).getUsername();
            } else {
                email = principal.toString();
            }
            // Lấy thông tin user từ database hoặc service
            User user = userService.findByEmail(email);
            // Thực hiện các thao tác với thông tin người dùng
            System.out.println(user.getEmail());
            session.setAttribute("email", user.getEmail());
            session.setAttribute("userId", user.getId());
        } catch (Exception e) {

        }

        model.addAttribute("products", productService.getAllProduct());
        model.addAttribute("categories", categoryService.getAllCategory());

        return "index";
    }

    @GetMapping("/shop")
    public String shop(Model model, HttpSession session) {
        model.addAttribute("categories", categoryService.getAllCategory());
        model.addAttribute("products", productService.getAllProduct());
        session.setAttribute("session", session);
        return "shop";
    }
    @GetMapping("/jsonpro")
    public ResponseEntity<Model> jsonAll(Model model, HttpSession session){
        model.addAttribute("categoty", categoryService.getAllCategory());
        model.addAttribute("products", productService.getAllProduct());
        session.setAttribute("session", session);
        return ResponseEntity.ok(model);
    }
    @GetMapping("/shop/category/{id}")
    public String shopByCategory(Model model, @PathVariable int id, HttpSession session) {
        model.addAttribute("categories", categoryService.getAllCategory());
        model.addAttribute("products", productService.getAllProductsByCategoryId(id));
        session.setAttribute("session", session);
        return "shop";
    }

    @GetMapping("/shop/viewproduct/{id}")
    public String viewProductDetail(Model model, @PathVariable int id, HttpSession session) {
        model.addAttribute("product", productService.getProductById(id).get());
        session.setAttribute("session", session);

        return "viewProduct";

    }

    @GetMapping("/shop/search")
    public String search(@RequestParam String keyword, Model model) {
        keyword = keyword.trim();
        List<Product> results = productService.search(keyword);
        model.addAttribute("categories", categoryService.getAllCategory());
        model.addAttribute("products", results);

        return "shop";
    }
}
