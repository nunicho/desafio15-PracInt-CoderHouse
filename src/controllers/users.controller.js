//const UserService = require("../services/users.service.js");
const mongoose = require("mongoose");
const UsersRepository = require("../dao/repository/users.repository")

// DOTENV
const config = require("../config/config.js");

const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const CustomError = require("../utils/customError.js");
const tiposDeError = require("../utils/tiposDeError.js");

const createUser = async (userData) => {
  try {
    const user = await UsersRepository.createUser(userData);
    return user;
  } catch (error) {
    throw new CustomError(
      "ERROR_CREAR_USUARIO",
      "Error al crear usuario",
      tiposDeError.ERROR_INTERNO_SERVIDOR,
      error.message
    );
  }

}

const getUserByEmail = async (email) => {
  try {
    const user = await UsersRepository.getUserByEmail(email);
    return user;
  } catch (error) {
    throw new CustomError(
      "ERROR_OBTENER_USUARIO",
      "Error al obtener usuario por correo electrónico",
      tiposDeError.ERROR_INTERNO_SERVIDOR,
      error.message
    );
  }
}


const getUsers = async (req, res) => {
  try {
    const users = await UsersRepository.getUsers();
    res.status(200).json(users);
  } catch (error)  {
    throw new CustomError(
      "ERROR_OBTENER_USUARIOS",
      "Error al obtener usuarios",
      tiposDeError.ERROR_INTERNO_SERVIDOR,
      error.message
    );
  }
};

const updateUser = async (req, res) => {
  try {
    const userId = req.params.userId;
    const userData = req.body;
    const updatedUser = await UsersRepository.updateUser(userId, userData);
    if (!updatedUser) {
      throw new CustomError(
        "USUARIO_NO_ENCONTRADO",
        "Usuario no encontrado",
        tiposDeError.ERROR_RECURSO_NO_ENCONTRADO,
        `No se encontró un usuario con ID ${userId}`
      );
    } else {
      res.status(200).json(updatedUser);
    }
  } catch (error) {
    throw new CustomError(
      "ERROR_ACTUALIZAR_USUARIO",
      "Error al actualizar usuario",
      tiposDeError.ERROR_INTERNO_SERVIDOR,
      error.message
    );
  }
};

const deleteUser = async (req, res) => {
  try {
    const userId = req.params.userId;
    await UsersRepository.deleteUser(userId);
    res.status(204).end();
  } catch (error) {
    throw new CustomError(
      "ERROR_ELIMINAR_USUARIO",
      "Error al eliminar usuario",
      tiposDeError.ERROR_INTERNO_SERVIDOR,
      error.message
    );
  }
};

const secret = config.SECRET;


const updatePassword = async (req, res) => {
  try {
    const token = req.params.token;
    const newPassword = req.body.newPassword;
    let errorMessage = null;

    // Decodificar el token para obtener la información necesaria
    const decodedToken = jwt.verify(token, secret);

    // Verificar si el token ha expirado
if (decodedToken.exp < Date.now() / 1000) {
      // Almacenar el mensaje de error antes de la redirección
      errorMessage = "Error al actualizar la contraseña. - Token expirado";
      // Redirigir a forgotPassword si el token ha expirado
      return res.redirect('/forgotPassword');
    }
    const user = await UsersRepository.getUserByEmail(decodedToken.email);
    // if (
    //   !user ||
    //   user.reset_password_token !== token ||
    //   user.reset_password_expires < Date.now()
    // ) {
    //   throw new CustomError(
    //     "TOKEN_INVALIDO",
    //     "Token inválido o caducado",
    //     tiposDeError.ERROR_NO_AUTORIZADO,
    //     "El token proporcionado no es válido o ha caducado."
    //   );
    // }

    const isSamePassword = await bcrypt.compare(newPassword, user.password);

    if (isSamePassword) {
      throw new CustomError(
        "CONTRASENA_ANTIGUA",
        "Contraseña igual a la actual",
        tiposDeError.ERROR_NO_AUTORIZADO,
        "La nueva contraseña no puede ser igual a la contraseña actual."
      );
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.reset_password_token = null;
    user.reset_password_expires = null;

    await user.save();
    // res.status(200).render("login", {
    //   successPasswordMessage:
    //     "Contraseña actualizada correctamente.",
    //   estilo: "login.css",
    // });
    res.status(200).send("Contraseña actualizada correctamente.");
  } catch (error) {
    if (error.name === "TOKEN_EXPIRADO") {
      res
        .status(400)
        .send("Error al actualizar la contraseña. - Token expirado");
    } else if (error.name === "CONTRASENA_ANTIGUA") {
      res
        .status(400)
        .send("La nueva contraseña no puede ser igual a la contraseña actual.");
    } else {
      console.error(error);
      res.status(400).send("Error al actualizar la contraseña.");
    }
  }
};


module.exports = {
  createUser,
  getUserByEmail,
  getUsers,
  updateUser,
  deleteUser,
  updatePassword,
};


/*
//const UserService = require("../services/users.service.js");
const mongoose = require("mongoose");
const UsersRepository = require("../dao/repository/users.repository")

const createUser = async (userData) => {
  try {
    const user = await UsersRepository.createUser(userData);
    return user;
  } catch (error) {
    throw error;
  }
}

const getUserByEmail = async (email) => {
  try {
    const user = await UsersRepository.getUserByEmail(email);
    return user;
  } catch (error) {
    throw error;
  }
}


const getUsers = async (req, res) => {
  try {
    const users = await UsersRepository.getUsers();
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ error: "Error fetching users" });
  }
};

const updateUser = async (req, res) => {
  try {
    const userId = req.params.userId;
    const userData = req.body;
    const updatedUser = await UsersRepository.updateUser(userId, userData);
    if (!updatedUser) {
      res.status(404).json({ error: "User not found" });
    } else {
      res.status(200).json(updatedUser);
    }
  } catch (error) {
    res.status(500).json({ error: "Error updating user" });
  }
};

const deleteUser = async (req, res) => {
  try {
    const userId = req.params.userId;
    await UsersRepository.deleteUser(userId);
    res.status(204).end();
  } catch (error) {
    res.status(500).json({ error: "Error deleting user" });
  }
};




module.exports = {
  createUser,
  getUserByEmail,
  getUsers,
  updateUser,
  deleteUser,
 };

*/