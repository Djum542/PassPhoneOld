//package net.codejava.user.api;
//
//import java.net.URI;
//
//import javax.validation.Valid;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.ResponseEntity;
//import org.springframework.ui.Model;
//import org.springframework.web.bind.annotation.*;
//
//import net.codejava.user.User;
//
//@RestController
//@RequestMapping("/register")
//public class UserApi {
//
//	@Autowired private UserService service;
//
//	@PutMapping("/users")
//	public ResponseEntity<?> createUser(@RequestBody @Valid User user) {
//		User createdUser = service.save(user);
//		URI uri = URI.create("/users/" + createdUser.getId());
//
//		UserDTO userDto = new UserDTO(createdUser.getId(), createdUser.getEmail());
//
//		return ResponseEntity.created(uri).body(userDto);
//	}
//	 	@GetMapping
//	public String showRegister(Model model){
//		model.addAttribute("user", new User());
//	return "register";
//	}
////	@PostMapping
////	public String registerUserAccount(@ModelAttribute("user")  User users, Model model){
////		try{
////			if (service.findByEmail(users.getEmail() != null)){
////				model.addAttribute("success", false);
////			}
////
////		}catch (Exception e){
////			System.out.println(e);
////		}
////		return "redirect:/register?success";
////	}
//}
