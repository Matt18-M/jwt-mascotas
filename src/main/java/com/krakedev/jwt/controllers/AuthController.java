package com.krakedev.jwt.controllers;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repositories.UsuarioRepository;
import com.krakedev.jwt.services.UsuarioService;
import com.krakedev.jwt.JwtUtil;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UsuarioService usuarioService;
    private final UsuarioRepository usuarioRepository;

    public AuthController(UsuarioService usuarioService, UsuarioRepository usuarioRepository) {
        this.usuarioService = usuarioService;
        this.usuarioRepository = usuarioRepository;
    }

    @PostMapping("/registrar")
    public ResponseEntity<?> registrar(@RequestBody Usuario usuario) {

        try {

            Usuario usuarioNuevo = usuarioService.guardar(usuario);

            return ResponseEntity.status(HttpStatus.CREATED).body(usuarioNuevo);

        } catch (Exception e) {

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al registrar usuario: " + e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credenciales) {

        String username = credenciales.get("username");
        String password = credenciales.get("password");

        boolean autenticado = usuarioService.autenticar(username, password);

        if (autenticado) {

            Usuario usuario = usuarioRepository.findByUsername(username).get();

            String token = JwtUtil.generarToken(usuario.getUsername(), usuario.getRol());

            return ResponseEntity.ok(Map.of("token", token));

        } else {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Usuario o Contraseña incorrecta");
        }
    }

    @GetMapping("/perfil")
    public ResponseEntity<?> verPerfil(@RequestHeader(value = "Authorization", required = false) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Acceso Denegado: Debes proveer un token Bearer valido en la cabecera Authorization");
        }

        String token = authHeader.substring(7);

        DecodedJWT datosToken = JwtUtil.validarToker(token);

        if (datosToken == null) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Acceso Denegado: token Invalido o Expirado");
        }

        String usuario = datosToken.getSubject();

        String rol = datosToken.getClaim("rol").asString();

        return ResponseEntity.ok(Map.of(
                "Mensaje", "Bienvenido al sistema protegido por JWT del Refugio Patitas al Rescate",
                "Usuario", usuario,
                "Rol", rol,
                "Estatus", "Autenticado Exitosamente"
        ));
    }
}