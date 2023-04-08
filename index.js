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
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 3001;
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

mongoose.connect(MONGO_URI);

const db = mongoose.connection;

// TODO: Create new Mongo Models and figure out key mgmt

// app stuff
app.use(express.json({ limit: "50mb" }));
app.use(helmet());

const cors = require("cors");
const KeyModel = require("./models/keys.js");
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
app.post("/api/register", authAPI(API_KEY), async (req, res) => {
  if (!validateParams(req.body, ["username", "password"])) {
    console.log("/api/register: wrong input");
    return res.status(400);
  }

  var new_user = new UserModel({
    username: req.body.username,
    admin: true,
  });
  new_user.password = new_user.generateHash(req.body.password);

  // Get RSA keys and add to DB
  const keyPair = generateRSAKeys();
  console.log(keyPair);
  new_user.privateKey = keyPair.privateKey;

  var keyRing = new KeyModel({
    username: req.body.username,
    publicKey: keyPair.publicKey,
  });
  await keyRing
    .save()
    .then(() => {
      console.log(keyRing.username + "'s key has been added");
    })
    .catch((err) => {
      console.log(err);
      return res.status(500).json({
        msg: "error adding keys",
        status: 401,
      });
    });
  // if username is unique create new
  // user, else send 401 error
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
      // password is correct
      const token = jwt.sign({ username: req.body.username }, PRIVATE_KEY, {
        expiresIn: "1hr",
      });
      return res.json({
        status: 200,
        token: token,
      });
    }
  });
});

// add steg image to db
app.post("/api/upload", authToken, upload.single("file"), async (req, res) => {
  //console.log(req.file);
  //console.log(req.body);

  var new_file = new FileModel({
    filename: req.body.filename,
    encrypted: false,
    file: {
      data: fs.readFileSync("uploads/" + req.file.filename),
      contentType: req.file.mimetype,
    },
  });

  new_file.hash = new_file.hashWithSHA3(new_file.file.data);
  //console.log(new_file.file.data);

  await new_file
    .save()
    .then(() => {
      removeFileFromMulterFolder(req.file.filename);
      return res.status(200).json({
        msg: "file added",
        status: 200,
        //data: req.body.file,
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
app.get("/api/getFiles", authToken, async (req, res) => {
  try {
    console.log("Loading Files to Client");
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

app.get("/api/keys/getAllPublic", authToken, async (req, res) => {
  try {
    console.log("Loading Public Keys to Client");
    const pubKeys = await KeyModel.find();
    res.status(200).json(pubKeys);
  } catch (err) {
    console.log("Error Public Keys to Client");
    res.status(500).json({ message: err.message });
  }
});

app.post("/api/encrypt", authToken, (req, res) => {
  if (!validateParams(req.body, ["encryptStyle", "key", "fileID"])) {
    console.log("/api/encrypt: wrong input");
    return res.status(400);
  }
  FileModel.findOne({ _id: req.body.fileID }).then((file) => {
    if (file == null) {
      return res.status(404).json({
        msg: "File not Found",
        status: 404,
      });
    } else if (req.body.encryptStyle === 1) {
      // AES
    } else if (req.body.encryptStyle === 2) {
      // DES
    } else if (req.body.encryptStyle === 3) {
      // RSA, Encrypt with passed PUBLIC key
      try {
        file.encryptWithRSA(req.body.key);

        console.log("File " + file.filename + " encrypted with RSA!");
        res.status(200).send();
        return;
        console.log("here2");
      } catch {
        (err) => {
          console.log(err);
          res.status(500).json({
            msg: "Failed to Encrypt File",
            status: 500,
          });
        };
      }
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

app.listen(PORT, () => {
  console.log("Server Running at: " + PORT);
});
