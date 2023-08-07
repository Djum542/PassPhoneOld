package com.gdu.nhom1.shopproject.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.gdu.nhom1.shopproject.dto.ProductDTO;
import com.gdu.nhom1.shopproject.models.Category;
import com.gdu.nhom1.shopproject.models.Product;
import com.gdu.nhom1.shopproject.models.User;
import com.gdu.nhom1.shopproject.services.CategoryService;
import com.gdu.nhom1.shopproject.services.ProductService;
import com.gdu.nhom1.shopproject.services.UserService;

@Controller
public class AdminController {  
    // public static String uploadDir = System.getProperty("user.dir") + "/src/main/resources/static/productImages";

//    @Autowired // Tiêm phụ thuộc CategoryService
//    CategoryService categoryService;
//
//    @Autowired // Tiêm phụ thuộc ProductService
//    ProductService productService;
//
//    @Autowired // Tiêm phụ thuộc ProductService
//    UserService userService;
//
//    // Đăng ký xử lý http GET
//    // GetMapping mapping the route '/admin' to the following controller
//    @GetMapping("/admin")
//    public String adminHome() {
//        return "adminHome";
//    }
//
//    @GetMapping("/admin/categories")
//    public String getCategories(Model model) {
//        model.addAttribute("categories", categoryService.getAllCategory());
//
//        return "categories";
//    }
//
//    @GetMapping("/admin/categories/add")
//    public String getCategoriesAdd(Model model) {
//        model.addAttribute("category", new Category());
//        return "categoriesAdd";
//    }
//
//    @PostMapping("/admin/categories/add")
//    public String postCategoriesAdd(@ModelAttribute("category") Category category) {
//        categoryService.addCategory(category);
//        return "redirect:/admin/categories"; // Chuyển hướng về trang categories
//    }
//
//    @GetMapping("/admin/categories/delete/{id}")
//    public String deleteCategory(@PathVariable int id) {
//        categoryService.removeCategoryById(id);
//        return "redirect:/admin/categories";
//    }
//
//    @GetMapping("/admin/categories/update/{id}")
//    public String updateCategory(@PathVariable int id, Model model) {
//        Category category = categoryService.getCategoryById(id).get();
//        model.addAttribute("category", category);
//        return "categoriesAdd";
//    }
//
//    @GetMapping("/admin/products")
//    public String getProducts(Model model) {
//        model.addAttribute("products", productService.getAllProduct());
//        return "products";
//    }
//
//    @GetMapping("/admin/products/add")
//    public String addProduct(Model model) {
//        model.addAttribute("productDTO", new ProductDTO());
//        model.addAttribute("categories", categoryService.getAllCategory());
//        return "productsAdd";
//    }
//
//    @PostMapping("/admin/products/add")
//    public String postProductAdd(@ModelAttribute("productDTO") ProductDTO productDTO) {
//        Product product = new Product();
//        product.setId(productDTO.getId());
//        product.setName(productDTO.getName());
//        product.setCategory(categoryService.getCategoryById(productDTO.getCategoryId()).get());
//        product.setPrice(productDTO.getPrice());
//        product.setQuantity(productDTO.getQuantity());
//        // product.setWeight(productDTO.getWeight());
//        product.setDescription(productDTO.getDescription());
//
//        product.setImageName(productDTO.getImageName());
//        productService.addProduct(product);
//        return "redirect:/admin/products";
//    }
//
//    @GetMapping("/admin/product/delete/{id}")
//    public String deleteProduct(@PathVariable long id) {
//        productService.removeProductById(id);
//        return "redirect:/admin/products";
//    }
//
//    @GetMapping("/admin/product/update/{id}")
//    public String updateProduct(@PathVariable long id, Model model) {
//        Product product = productService.getProductById(id).get();
//        ProductDTO productDTO = new ProductDTO();
//        productDTO.setId(product.getId());
//        productDTO.setName(product.getName());
//        productDTO.setCategoryId(product.getCategory().getId());
//        productDTO.setPrice(product.getPrice());
//        productDTO.setQuantity(product.getQuantity());
//        productDTO.setDescription(product.getDescription());
//        productDTO.setImageName(product.getImageName());
//        model.addAttribute("categories", categoryService.getAllCategory());
//        model.addAttribute("productDTO", productDTO);
//        return "productsAdd";
//    }
//
//    @GetMapping("/admin/viewproduct/{id}")
//    public String viewProduct(@PathVariable long id,Model model) {
//        model.addAttribute("product", productService.getProductById(id).get());
//        return "viewProductAdmin";
//    }
//
//    @GetMapping("/products/search")
//    public String searchProduct(@RequestParam String keyword, Model model) {
//        List<Product> results = productService.search(keyword);
//        model.addAttribute("products", results);
//
//        return "products";
//    }
//
//    @GetMapping("/categories/search")
//    public String searchCategory(@RequestParam String keyword, Model model) {
//        List<Category> results = categoryService.search(keyword);
//        model.addAttribute("categories", results);
//
//        return "categories";
//    }
//
//    @GetMapping("/admin/users/search")
//    public String searchUser(@RequestParam String keyword, Model model) {
//        List<User> results = userService.search(keyword);
//        model.addAttribute("users", results);
//
//        return "users";
//    }
}
