package com.app.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.app.exceptions.UserNotFoundException;
import com.app.payloads.LoginCredentials;
import com.app.payloads.UserDTO;
import com.app.payloads.UserInfoDTO;
import com.app.security.JWTUtil;
import com.app.services.UserService;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api")
@SecurityRequirement(name = "E-Commerce Application")
@CrossOrigin
public class AuthController {

	@Autowired
	private UserService userService;

	@Autowired
	private JWTUtil jwtUtil;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@PostMapping("/register")
	public ResponseEntity<UserInfoDTO> registerHandler(@Valid @RequestBody UserDTO user) throws UserNotFoundException {
		String encodedPass = passwordEncoder.encode(user.getPassword());

		user.setPassword(encodedPass);

		UserDTO userDTO = userService.registerUser(user);

		String token = jwtUtil.generateToken(userDTO.getEmail());

		UserInfoDTO userInfo = new UserInfoDTO(token, userDTO);

		return new ResponseEntity<UserInfoDTO>(userInfo, HttpStatus.OK);
	}	

	@PostMapping("/login")
	public ResponseEntity<UserInfoDTO> loginHandler(@Valid @RequestBody LoginCredentials credentials) {

		UsernamePasswordAuthenticationToken authCredentials = new UsernamePasswordAuthenticationToken(
				credentials.getEmail(), credentials.getPassword());

		authenticationManager.authenticate(authCredentials);
		UserDTO userDetails = userService.getUserByEmail(credentials.getEmail());
		String token = jwtUtil.generateToken(credentials.getEmail());

		UserInfoDTO userInfo = new UserInfoDTO(token, userDetails);
		return new ResponseEntity<UserInfoDTO>(userInfo, HttpStatus.OK);
	}
}