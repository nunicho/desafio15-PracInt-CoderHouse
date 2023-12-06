//const UserService = require("../services/users.service.js");
const mongoose = require("mongoose");
const UsersRepository = require("../dao/repository/users.repository")

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

const secret = "palabra-secreta";


const updatePassword = async (req, res) => {
  try {
    const token = req.params.token;
    const newPassword = req.body.newPassword;
    console.log(`La New password es: ${newPassword}`)
    // Decodificar el token para obtener la información necesaria
    const decodedToken = jwt.verify(token, secret); // Utiliza la misma palabra secreta

    // Obtener el usuario por ID del token
    const user = await UsersRepository.getUserByEmail(decodedToken.email);
    console.log(`decodedToken.email es igual a  : ${decodedToken.email}`);
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

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Actualizar la contraseña del usuario con la contraseña hasheada
    user.password = hashedPassword;
    user.reset_password_token = null;
    user.reset_password_expires = null;

    await user.save();

    res.status(200).send("Contraseña actualizada correctamente.");
  } catch (error) {
    // Manejar errores y enviar la respuesta correspondiente
    console.error(error);
    res.status(400).send("Error al actualizar la contraseña.");
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