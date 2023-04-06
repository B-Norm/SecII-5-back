const mongoose = require("mongoose");
const crypto = require("crypto");

const keySchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
    },
    publicKey: {
      type: String,
      required: true,
    },
  },
  { collection: "keys" }
);

const KeyModel = mongoose.model("keys", keySchema);
module.exports = KeyModel;
