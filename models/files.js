const mongoose = require("mongoose");
const crypto = require("crypto");

// TODO: Use the encrypted status to change URL/ Change server reaction
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

// IV Creation
fileSchema.methods.createIV = function (style, str) {
  if (style === "3DES" && !str) {
    console.log("NO USER INPUT");
    this.iv = crypto.randomBytes(8);
  } else if (style === "3DES" && str) {
    this.iv = crypto.createHash("md5").update(str).digest("hex").slice(0, 8);
    console.log(this.IV);
  } else if (style === "AES" && !str) {
    this.iv = crypto.randomBytes(16);
    console.log(this.IV);
  } else {
    this.iv = crypto.createHash("md5").update(str).digest("hex");
    console.log(this.IV);
  }
  this.save();
};

// AES Encryption and Decryption
fileSchema.methods.encryptWithAES = function (key) {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, this.iv);
  this.file.data = Buffer.concat([
    cipher.update(this.file.data),
    cipher.final(),
  ]);
  this.save();
  return;
};

fileSchema.methods.decryptWithAES = function (key) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, this.iv);
  let decrypted = decipher.update(this.file.data);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  if (this.hash === this.hashWithSHA3(decrypted)) {
    this.file.data = decrypted;
    this.save();
    return true;
  }
  return false;
};

// 3-DES Encryption and Decryption
fileSchema.methods.encryptWith3DES = function (key) {
  const cipher = crypto.createCipheriv("des-ede3-cbc", key, this.iv);
  this.file.data = Buffer.concat([
    cipher.update(this.file.data),
    cipher.final(),
  ]);
  this.save();
  return;
};

fileSchema.methods.decryptWith3DES = function (key) {
  const decipher = crypto.createDecipheriv("des-ede3-cbc", key, this.iv);
  let decrypted = decipher.update(this.file.data);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  if (this.hash === this.hashWithSHA3(decrypted)) {
    this.file.data = decrypted;
    this.save();
    return true;
  }
  return false;
};

// SHA-3 Hashing
fileSchema.methods.hashWithSHA3 = (file) => {
  const hash = crypto.createHash("sha3-256");
  hash.update(file);
  return hash.digest("hex");
};

const FileModel = mongoose.model("files", fileSchema);
module.exports = FileModel;
