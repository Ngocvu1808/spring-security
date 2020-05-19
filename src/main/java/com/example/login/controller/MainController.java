package com.example.login.controller;

import java.security.Principal;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.example.login.utils.WebUtils;

@Controller
public class MainController {

	@RequestMapping(value = {"/", "/welcome"}, method = RequestMethod.GET)
	public String welcome(Model model) {
		model.addAttribute("title", "Welcome");
		model.addAttribute("message", "This is welcome page!");
		return "welcomePage";
	}
	
	@RequestMapping(value = "/admin", method = RequestMethod.GET)
	public String adminPage(Model model, Principal principal) {
		
		User loginedUser = (User)((Authentication)principal).getPrincipal();
		String userInfo = WebUtils.toString(loginedUser);
		model.addAttribute("userInfo", userInfo);
		
		return "adminPage";
	}
	
	
	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public String loginPage(Model model) {
		
		 return "loginPage";
	}
	
	@RequestMapping(value = "/userInfo", method = RequestMethod.GET)
	public String userInfo(Model model, Principal principal) {
		//after user login successfully, there will be principal
		String userName = principal.getName();
		
		System.out.println("User Name: "+ userName);
		
		User loginedUser = (User) ((Authentication) principal).getPrincipal();
		
		String userInfo = (String)WebUtils.toString(loginedUser);
		model.addAttribute("userInfo", userInfo);
		
		return "userInfoPage";
	}
	
	@RequestMapping
	public String accessDenied(Model model, Principal principal) {
		if(principal != null) {
			User loginedUser = (User)((Authentication)principal).getPrincipal();
			
			String userInfo = WebUtils.toString(loginedUser);
			
			model.addAttribute("userInfo", userInfo);
			
			String message = "Hi "+ principal.getName()
				+ "<br> You don't have permission to access this page!";
			
			model.addAttribute("message", message);
		}
		return "403Page";
	}
}
