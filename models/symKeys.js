const mongoose = require("mongoose");
const crypto = require("crypto");

const symKeySchema = new mongoose.Schema(
  {
    keyName: {
      type: String,
      require: true,
    },
    username: {
      type: String,
      required: true,
    },
    symKey: {
      type: String,
      required: true,
    },
    style: {
      type: String,
      required: true,
    },
    ignoreMiddleware: {
      type: Boolean,
      default: false,
    },
  },
  { collection: "symKeys" }
);

symKeySchema.pre("save", async function (next) {
  if (this.ignoreMiddleware) {
    return next();
  }
  const name = this.keyName;
  const regex = new RegExp(`^${name}-(\\d+)$`, "i");
  const model = mongoose.model("symKeys");
  const existingKeys = await model.find({ keyName: regex }).exec();
  let highestNumber = 0;

  existingKeys.forEach((key) => {
    const match = key.keyName.match(regex);
    if (match[1]) {
      const number = parseInt(match[1]);
      if (number > highestNumber) {
        highestNumber = number;
      }
    }
  });

  if (highestNumber > 0) {
    this.keyName = `${name}-${highestNumber + 1}`;
  } else {
    this.keyName = `${name}-1`;
  }

  next();
});

const SymKeyModel = mongoose.model("symKeys", symKeySchema);
module.exports = SymKeyModel;
