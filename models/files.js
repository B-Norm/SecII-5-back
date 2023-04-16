const mongoose = require("mongoose");
const forge = require("node-forge");

const fileSchema = new mongoose.Schema(
  {
    filename: {
      type: String,
      required: true,
    },
    file: {
      data: Buffer,
      contentType: String,
      //required: true,
    },
    encrypted: {
      type: Boolean,
    },
    iv: {
      type: String,
    },
    hash: {
      type: String,
      required: true,
    },
  },
  { collection: "files" }
);

// SHA-256 Hashing
fileSchema.methods.hashWithSHA3 = (file) => {
  const hash = forge.md.sha256.create();
  hash.update(file);
  return hash.digest().toHex();
};

const FileModel = mongoose.model("files", fileSchema);
module.exports = FileModel;
