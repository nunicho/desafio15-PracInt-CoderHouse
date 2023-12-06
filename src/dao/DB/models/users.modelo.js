const mongoose = require("mongoose");


const modeloUsers = mongoose.model(
  "users",
  new mongoose.Schema({
    first_name: String,
    last_name: String,
    email: {
      type: String,
      unique: true,
    },
    age: Number,
    password: String,
    cart: String,
    role: { type: String, enum: ["user", "premium"], default: "user" },
  })
);

module.exports = modeloUsers;