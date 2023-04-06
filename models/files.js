const mongoose = require("mongoose");

const fileSchema = new mongoose.Schema(
  {
    fileName: {
      type: String,
      required: true,
    },
    file: {
      type: Buffer,
      required: true,
    },
    sendTo: {
      type: String,
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
  } else if (style === "AES" && !str) {
    this.iv = crypto.randomBytes(16);
  } else {
    this.iv = crypto.createHash("md5").update(str).digest("hex");
  }
};

// AES Encryption and Decryption
fileSchema.methods.encryptWithAES = function (key) {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, this.iv);
  this.file = Buffer.concat([cipher.update(this.file), cipher.final()]);
};

fileSchema.methods.decryptWithAES = function (key) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, this.iv);
  let decrypted = decipher.update(encryptedData);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  if (this.hash === this.hashWithSHA3(decrypted)) {
    this.file = decrypted;
  }
  return false;
};

// 3-DES Encryption and Decryption
fileSchema.methods.encryptWith3DES = function (key) {
  const cipher = crypto.createCipheriv("des-ede3-cbc", key, this.iv);
  this.file = Buffer.concat([cipher.update(this.file), cipher.final()]);
};

fileSchema.methods.decryptWith3DES = function (key) {
  const decipher = crypto.createDecipheriv("des-ede3-cbc", key, this.iv);
  let decrypted = decipher.update(this.file);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  if (this.hash === this.hashWithSHA3(decrypted)) {
    this.file = decrypted;
  }
  return false;
};

// RSA Encryption and Decryption
fileSchema.methods.encryptWithRSA = function (publicKey) {
  this.file = crypto.publicEncrypt(publicKey, this.file);
};

fileSchema.methods.decryptWithRSA = function (privateKey) {
  this.file = crypto.privateDecrypt(privateKey, this.file);
};

// SHA-3 Hashing
fileSchema.methods.hashWithSHA3 = function (file) {
  const hash = crypto.createHash("sha3-256");
  hash.update(file);
  return hash.digest();
};

const FileModel = mongoose.model("files", fileSchema);
module.exports = FileModel;
