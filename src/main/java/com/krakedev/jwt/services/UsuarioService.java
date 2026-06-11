package com.krakedev.jwt.services;

import java.util.List;
import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repositories.UsuarioRepository;

@Service
public class UsuarioService {

    private final UsuarioRepository repository;

    public UsuarioService(UsuarioRepository repository) {
        this.repository = repository;
    }

    // Guardar usuario con contraseña encriptada
    public Usuario guardar(Usuario usuario) {

        String passwordEncriptado = BCrypt.hashpw(usuario.getPassword(), BCrypt.gensalt());

        usuario.setPassword(passwordEncriptado);

        return repository.save(usuario);
    }

    // Listar usuarios
    public List<Usuario> listar() {
        return repository.findAll();
    }

    // Buscar por id
    public Usuario buscar(Long id) {

        Optional<Usuario> resultado = repository.findById(id);

        return resultado.orElse(null);
    }

    // Buscar por username
    public Usuario buscarPorUsername(String username) {

        Optional<Usuario> resultado = repository.findByUsername(username);

        return resultado.orElse(null);
    }

    // Autenticar usuario con BCrypt
    public boolean autenticar(String username, String password) {

        Optional<Usuario> usuarioOpt = repository.findByUsername(username);

        if (usuarioOpt.isPresent()) {

            Usuario usuario = usuarioOpt.get();

            if (BCrypt.checkpw(password, usuario.getPassword())) {
                return true;
            }
        }

        return false;
    }

    // Eliminar usuario
    public boolean eliminar(Long id) {

        Usuario usuario = buscar(id);

        if (usuario == null) {
            return false;
        }

        repository.deleteById(id);
        return true;
    }
}