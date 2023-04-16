require("dotenv").config();

const express = require("express");
const multer = require("multer");
const fileUpload = require("express-fileupload");
const helmet = require("helmet");
const fs = require("fs");
const app = express();
const mongoose = require("mongoose");
const UserModel = require("./models/users.js");
const FileModel = require("./models/files.js");
const API_KEY = process.env.API_KEY;
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const SERVER_PRIVATE_KEY = process.env.SERVER_PRIVATE_KEY;
const SERVER_PUBLIC_KEY = process.env.SERVER_PUBLIC_KEY;
const SERVER_AES_KEY = process.env.SERVER_AES_KEY;
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 3001;
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const forge = require("node-forge");

mongoose.connect(MONGO_URI);

const db = mongoose.connection;

// app stuff
app.use(express.json({ limit: "50mb" }));
app.use(helmet());

const cors = require("cors");
const KeyModel = require("./models/keys.js");
const SymKeyModel = require("./models/symKeys.js");
app.use(cors());

// CHECK IF USING API_KEY
const authAPI = (API_KEY) => {
  return (req, res, next) => {
    //console.log("Authorization Middleware");
    const token = req.headers["x-my-api-key"] || req.headers["api_key"];
    if (!token) {
      return res.status(403).json({
        status: 403,
        message: "Missing Authorization header",
        SERVER_API: API_KEY,
        HEADERS: req.headers,
      });
    } else {
      if (API_KEY != token) {
        return res.status(401).json({
          status: 401,
          message: "Invalid API Key",
        });
      } else {
        next();
      }
    }
  };
};

function authToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) {
    console.log("Token failed");
    return res.sendStatus(401);
  }
  jwt.verify(token, PRIVATE_KEY, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}
const upload = multer({ dest: "uploads/" });

// Remove file with given filename from Multer upload folder
function removeFileFromMulterFolder(filename) {
  //const filePath = path.join("uploads/", filename);

  fs.unlink("uploads/" + filename, (err) => {
    if (err) {
      console.error(`Error deleting file:`, err);
    }
  });
}

// REGISTER USERS
//
//
app.post("/api/register", authAPI(API_KEY), async (req, res) => {
  if (!validateParams(req.body, ["username", "password"])) {
    console.log("/api/register: wrong input");
    return res.status(400);
  }

  var new_user = new UserModel({
    username: req.body.username,
    admin: false,
  });
  new_user.password = new_user.generateHash(req.body.password);

  await new_user
    .save()
    .then(() => {
      return res.json({
        msg: "User Created",
        status: 200,
      });
    })
    .catch((err) => {
      console.log(err);
      return res.status(401).json({
        msg: "username taken",
        status: 401,
      });
    });
});

app.post("/api/login", authAPI(API_KEY), async (req, res) => {
  if (!validateParams(req.body, ["username", "password"])) {
    console.log("/api/login: wrong input");

    return res.status(400);
  }

  /* db.on("error", (err) => {
    res
      .status(469)
      .res.json({ message: `Failed to connect to MongoDB Atlas: ${err}` });
  });

  db.once("open", () => {
    console.log("Connected to MongoDB Atlas");
  }); */

  UserModel.findOne({ username: req.body.username }).then((user) => {
    if (user == null) {
      res.status(401).json({
        msg: "username or password is incorrect",
        status: 401,
      });
    } else if (!user.validPassword(req.body.password, user.password)) {
      res.status(401).json({
        msg: "username or password is incorrect",
        status: 401,
      });
    } else {
      const token = jwt.sign({ username: req.body.username }, PRIVATE_KEY, {
        expiresIn: "1hr",
      });
      return res.json({
        status: 200,
        token: token,
        SERVER_PUBLIC_KEY: SERVER_PUBLIC_KEY,
      });
    }
  });
});

app.get("/api/getUsers", authToken, async (req, res) => {
  try {
    const users = await UserModel.find();
    const usernames = users.map((user) => ({
      title: "username",
      username: user.username,
    }));
    res.status(200).json(usernames);
  } catch (err) {
    console.log("Error loading usernames");
    res.status(500).json({ message: err.message });
  }
});

// add steg image to db
app.post("/api/upload", authToken, upload.single("file"), async (req, res) => {
  if (typeof req.body.filename === "undefined") {
    return res.status(500).json({
      msg: "No file Submited",
      status: 500,
    });
  }
  var new_file = new FileModel({
    filename: req.body.filename,
    encrypted: false,
    file: {
      data: fs.readFileSync("uploads/" + req.file.filename),
      contentType: req.file.mimetype,
    },
  });
  /* console.log("\\" + new_file.file.data.toJSON().data.toString() + "/");
  console.log(
    new_file.hashWithSHA3(new_file.file.data.toJSON().data.toString())
  );  */
  new_file.hash = new_file.hashWithSHA3(new_file.file.data);

  await new_file
    .save()
    .then(() => {
      removeFileFromMulterFolder(req.file.filename);
      return res.status(200).json({
        msg: "file added",
        status: 200,
      });
    })
    .catch((err) => {
      console.log(err);
      return res.status(401).json({
        msg: "File Error",
        status: 400,
        error: err,
      });
    });
});

// get all files from DB
//
//
app.get("/api/getFiles", authToken, async (req, res) => {
  try {
    // console.log("Loading Files to Client");
    const files = await FileModel.find();
    res.status(200).json(files);
  } catch (err) {
    console.log("Error sending files to client");
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/deleteAllFiles", authToken, async (req, res) => {
  try {
    console.log("Deleting all files from the database");
    const result = await FileModel.deleteMany();
    console.log(`${result.deletedCount} files deleted`);
    res.status(200).json({
      message: `${result.deletedCount} files deleted`,
    });
  } catch (err) {
    console.log("Error deleting files from the database");
    res.status(500).json({ message: err.message });
  }
});

// AES Stuff
//
//
app.post("/api/keys/shareSymKey", authToken, async (req, res) => {
  if (!validateParams(req.body, ["encryptKey", "keyName", "username"])) {
    console.log("/api/keys/storeSym: wrong input");
    return res.status(400);
  }
  const { encryptKey, keyName, username } = req.body;

  // decrypt key using server private and store in
  const sharedKey64 = asymDecrypt(encryptKey, SERVER_PRIVATE_KEY);

  // Store Sym key in DB
  var new_sym = new SymKeyModel({
    keyName,
    username,
    symKey: sharedKey64,
    style: keyName.split("-")[0],
  });
  new_sym.ignoreMiddleware = true;
  new_sym.save().then(() => {
    return res.status(200).json({
      msg: "Key added",
      status: 200,
    });
  });
});

app.post("/api/keys/storeSym", authToken, async (req, res) => {
  if (!validateParams(req.body, ["encryptKey", "style", "username"])) {
    console.log("/api/keys/storeSym: wrong input");
    return res.status(400);
  }
  // first decrypt encrypt key
  // TODO: Store in the DB encrypted and decrypt before sending back to client

  try {
    let symKey = asymDecrypt(req.body.encryptKey, SERVER_PRIVATE_KEY);
    const prefix = ["AES-", "3DES-"];
    let username = req.body.username;
    let name = prefix[req.body.style - 1] + username;
    var new_sym = SymKeyModel({
      keyName: name,
      username,
      symKey,
      style: prefix[req.body.style - 1].slice(0, -1),
    });
  } catch (err) {
    console.error(err);
  }
  await new_sym
    .save()
    .then(() => {
      return res.status(200).json({
        msg: "Key added",
        status: 200,
      });
    })
    .catch((err) => {
      console.log(err);
      return res.status(500).json({
        msg: "Key Save Error",
        status: 500,
        error: err,
      });
    });
});

app.post("/api/keys/getSym", authToken, async (req, res) => {
  // style: 1 = AES, 2 = 3DES, 3 = ALL
  if (!validateParams(req.body, ["style", "username"])) {
    console.log("/api/keys/getSym: wrong input");
    return res.status(400);
  }
  const { style, username } = req.body;
  if (style != 3) {
    const encryptStyle = ["AES", "3DES"];
    SymKeyModel.find({
      username,
      style: encryptStyle[style - 1],
    }).then((keys) => {
      KeyModel.findOne({ username: req.body.username }).then((pubKeys) => {
        const publicKey = pubKeys.publicKey;
        // Encrypt data with AES and send it with the IV at the front
        const keysString = JSON.stringify(keys);
        const aesEncryptedData = symEncrpytWithRand(keysString);

        // encrypt AES key with User's pubKey
        const keyEncrpyt = asymEncrypt(aesEncryptedData.key, publicKey);
        return res.status(200).json({
          encryptedData: aesEncryptedData.encryptedBase64,
          encryptedKey: keyEncrpyt,
        });
      });
    });
  } else {
    SymKeyModel.find({
      username,
    }).then((keys) => {
      KeyModel.findOne({ username: req.body.username }).then((pubKeys) => {
        const publicKey = pubKeys.publicKey;
        // Encrypt data with AES and send it with the IV at the front
        const keysString = JSON.stringify(keys);
        const aesEncryptedData = symEncrpytWithRand(keysString);

        // encrypt AES key with User's pubKey
        const keyEncrpyt = asymEncrypt(aesEncryptedData.key, publicKey);
        return res.status(200).json({
          encryptedData: aesEncryptedData.encryptedBase64,
          encryptedKey: keyEncrpyt,
        });
      });
    });
  }
});

app.post("/api/AES/encrypt", authToken, async (req, res) => {
  if (!validateParams(req.body, ["iv", "file", "fileID"])) {
    console.log("/api/AES/encrypt: wrong input");
    return res.status(400);
  }
  FileModel.findOne({ _id: req.body.fileID }).then((file) => {
    if (file == null) {
      return res.status(404).json({
        msg: "File not Found",
        status: 404,
      });
    } else {
      file.file.data = Buffer.from(req.body.file, "base64");
      file.iv = req.body.iv;
      file.encrypted = true;
      file.save();
      return res.status(200).send();
    }
  });
});

app.post("/api/AES/decrypt", authToken, async (req, res) => {
  if (!validateParams(req.body, ["file", "fileID"])) {
    console.log("/api/AES/decrypt: wrong input");
    return res.status(400);
  }
  FileModel.findOne({ _id: req.body.fileID }).then((file) => {
    if (file == null) {
      return res.status(404).json({
        msg: "File not Found",
        status: 404,
      });
    } else {
      file.file.data = Buffer.from(req.body.file, "base64");
      file.encrypted = false;
      file.iv = undefined;
      if (file.hashWithSHA3(file.file.data) === file.hash) {
        file.save();
        return res.status(200).send();
      } else {
        return res.status(500).json({
          msg: "File has been tampered",
          status: 500,
        });
      }
    }
  });
});

// 3DES Stuff
//
//
app.post("/api/3DES/encrypt", authToken, async (req, res) => {
  if (!validateParams(req.body, ["iv", "file", "fileID"])) {
    console.log("/api/3DES/encrypt: wrong input");
    return res.status(400);
  }
  FileModel.findOne({ _id: req.body.fileID }).then((file) => {
    if (file == null) {
      return res.status(404).json({
        msg: "File not Found",
        status: 404,
      });
    } else {
      file.file.data = Buffer.from(req.body.file, "base64");
      file.iv = req.body.iv;
      file.encrypted = true;
      file.save();
      return res.status(200).send();
    }
  });
});

app.post("/api/3DES/decrypt", authToken, async (req, res) => {
  if (!validateParams(req.body, ["file", "fileID"])) {
    console.log("/api/3DES/decrypt: wrong input");
    return res.status(400);
  }
  FileModel.findOne({ _id: req.body.fileID }).then((file) => {
    if (file == null) {
      return res.status(404).json({
        msg: "File not Found",
        status: 404,
      });
    } else {
      file.file.data = Buffer.from(req.body.file, "base64");
      file.encrypted = false;
      file.iv = undefined;
      if (file.hashWithSHA3(file.file.data) === file.hash) {
        file.save();
        return res.status(200).send();
      } else {
        return res.status(500).json({
          msg: "File has been tampered",
          status: 500,
        });
      }
    }
  });
});

// RSA Stuff
//
//
app.post("/api/keys/storePub", authAPI(API_KEY), async (req, res) => {
  if (!validateParams(req.body, ["username", "publicKey"])) {
    console.log("/api/keys/storePub: wrong input");
    return res.status(400);
  }

  var keyRing = new KeyModel({
    username: req.body.username,
    publicKey: req.body.publicKey,
  });
  await keyRing
    .save()
    .then(() => {
      console.log(keyRing.username + "'s key has been added");
      res.status(200).send();
      return;
    })
    .catch((err) => {
      console.log(err);
      return res.status(500).json({
        msg: "error adding keys",
        status: 401,
      });
    });
});

app.get("/api/keys/getAllPublic", authToken, async (req, res) => {
  try {
    //console.log("Loading Public Keys to Client");
    const pubKeys = await KeyModel.find();
    res.status(200).json(pubKeys);
  } catch (err) {
    console.log("Error Public Keys to Client");
    res.status(500).json({ message: err.message });
  }
});

app.post("/api/RSA/encrypt", authToken, async (req, res) => {
  if (!validateParams(req.body, ["file", "fileID"])) {
    console.log("/api/RSA/encrypt: wrong input");
    return res.status(400);
  }
  FileModel.findOne({ _id: req.body.fileID }).then((file) => {
    if (file == null) {
      return res.status(404).json({
        msg: "File not Found",
        status: 404,
      });
    } else {
      file.file.data = Buffer.from(req.body.file, "base64");
      file.encrypted = true;
      file.save();
      return res.status(200).send();
    }
  });
});

app.post("/api/RSA/decrypt", authToken, async (req, res) => {
  if (!validateParams(req.body, ["file", "fileID"])) {
    console.log("/api/RSA/decrypt: wrong input");
    return res.status(400);
  }
  FileModel.findOne({ _id: req.body.fileID }).then((file) => {
    if (file == null) {
      return res.status(404).json({
        msg: "File not Found",
        status: 404,
      });
    } else {
      file.file.data = Buffer.from(req.body.file, "base64");
      file.encrypted = false;
      if (file.hashWithSHA3(file.file.data) === file.hash) {
        file.save();
        return res.status(200).send();
      } else {
        return res.status(500).json({
          msg: "File has been tampered",
          status: 500,
        });
      }
    }
  });
});

// test for file integrity
app.post("/api/hash", authToken, async (req, res) => {
  if (!validateParams(req.body, ["fileID"])) {
    console.log("/api/hash: wrong input");
    return res.status(400);
  }
  FileModel.findOne({ _id: req.body.fileID }).then((file) => {
    //console.log(file.file.data.toJSON().data);
    if (file == null) {
      return res.status(404).json({
        msg: "File not Found",
        status: 404,
      });
    } else {
      return res.status(200).json({ hash: file.hash });
    }
  });
});

const validateParams = (body, params) => {
  let res = true;
  for (let i = 0; i < params.length; i++) {
    if (!body.hasOwnProperty(params[i])) {
      res = false;
      break;
    }
  }
  return res;
};

// generate RSA key pair
const generateRSAKeys = () => {
  // Generate a new RSA key pair with a modulus size of 2048 bits
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  // Convert the keys to PEM format
  const privateKeyPEM = privateKey.export({
    type: "pkcs1",
    format: "pem",
  });

  const publicKeyPEM = publicKey.export({
    type: "pkcs1",
    format: "pem",
  });

  // Return the keys as an object
  return {
    privateKey: privateKeyPEM,
    publicKey: publicKeyPEM,
  };
};

const asymEncrypt = (data, pubKey, returnType) => {
  const publicKeyObject = forge.pki.publicKeyFromPem(pubKey);

  const encryptedBuffer = publicKeyObject.encrypt(data);

  return encryptedBuffer;
};

const asymDecrypt = (encrypt64, privKey, returnType) => {
  let decryptedBuffer;
  try {
    const encryptedBuffer = forge.util.decode64(encrypt64);
    const privateKeyObject = forge.pki.privateKeyFromPem(privKey);
    decryptedBuffer = privateKeyObject.decrypt(encryptedBuffer);

    return decryptedBuffer;
  } catch (err) {
    console.log("Failed to decrypt key " + err.message);
  }
};

const symEncrpytWithRand = (data) => {
  const iv = forge.random.getBytesSync(16);
  const key = forge.random.getBytesSync(32);
  const cipher = forge.cipher.createCipher("AES-CBC", key);
  cipher.start({ iv: iv });
  cipher.update(forge.util.createBuffer(data));
  cipher.finish();
  const encryptedBase64 =
    forge.util.encode64(iv) + forge.util.encode64(cipher.output.getBytes());

  return { encryptedBase64, key };
};
app.listen(PORT, () => {
  console.log("Server Running at: " + PORT);
});
