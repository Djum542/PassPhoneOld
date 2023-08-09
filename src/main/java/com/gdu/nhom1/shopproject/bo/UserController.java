//package com.gdu.nhom1.shopproject.controllers;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Controller;
//import org.springframework.ui.Model;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.ModelAttribute;
//import org.springframework.web.bind.annotation.PathVariable;
//import org.springframework.web.bind.annotation.PostMapping;
//
//import com.gdu.nhom1.shopproject.dto.UserRegistrationDTO;
//import com.gdu.nhom1.shopproject.models.User;
//import com.gdu.nhom1.shopproject.services.UserService;
//
//@Controller
//public class UserController {
//    @Autowired
//    UserService userService;
//
////    @GetMapping("/admin/users")
////    public String listUsers(Model model) {
////        model.addAttribute("users", userService.findALL());
////        return "users";
////    }
//
////    @GetMapping("/admin/users/add")
////    public String addUser(Model model) {
////
////        model.addAttribute("userDTO", new UserRegistrationDTO());
////        return "userAdd";
////    }
////
////    @GetMapping("/admin/users/delete/{id}")
////    public String deleteUser(@PathVariable long id) {
////        userService.removeUserById(id);
////        return "redirect:/admin/users";
////    }
////
////
////    @GetMapping("/admin/users/update/{id}")
////    public String updateUser(@PathVariable long id, Model model) {
////        User user = userService.getUserById(id).get();
////        UserRegistrationDTO userDTO = new UserRegistrationDTO();
////        userDTO.setId(id);
////        userDTO.setFirstName(user.getFirstName());
////        userDTO.setLastName(user.getLastName());
////        userDTO.setEmail(user.getEmail());
////        userDTO.setPassword(user.getPassword());
////        model.addAttribute("isUpdate", true); // Thêm thông tin mới để xác định trường hợp sửa thông tin người dùng
////        model.addAttribute("userDTO", userDTO);
////        return "userAdd";
////    }
////
////    @PostMapping("/admin/users/add")
////    public String postUserAdd(@ModelAttribute("userDTO") UserRegistrationDTO userDTO) {
////        User user = new User();
////        user.setId(userDTO.getId());
////        user.setEmail(userDTO.getEmail());
////        user.setFirstName(userDTO.getFirstName());
////        user.setLastName(userDTO.getLastName());
////        user.setPassword(userDTO.getPassword());
////        userService.updateUser(user);
////        return "redirect:/admin/users";
////    }
//
//}
