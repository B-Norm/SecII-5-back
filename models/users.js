const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    admin: {
      type: Boolean,
    },
    privateKey: {
      type: String,
      require: true,
    },
    aesKeys: {
      type: Array,
      require: false,
    },
  },
  { collection: "users" }
);

// hash password
userSchema.methods.generateHash = (password) => {
  return bcrypt.hashSync(password, 10);
};

// varify password
userSchema.methods.validPassword = (password, hash) => {
  return bcrypt.compareSync(password, hash);
};

const UserModel = mongoose.model("users", userSchema);
module.exports = UserModel;
