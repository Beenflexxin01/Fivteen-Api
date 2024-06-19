const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const validator = require("validator");

const userSchema = new mongoose.Schema(
  {
    // name: {
    //   type: String,
    //   required: [true, "A user must have a name"],
    //   minlength: 3,
    // },

    email: {
      type: String,
      required: true,
      unique: true,
    },

    password: { type: String, required: true, minlength: 3, maxlength: 20 },
    isVerified: { type: Boolean, default: false },
    emailToken: { type: String },
  },
  { timestamps: true }
);

// STATIC SIGNUP METHOD
userSchema.static.signup = async function (email, password) {
  //VALIDATION
  if (!email || !password) throw new Error("All fields must be filled!");
  if (!validator.isEmail(email)) throw new Error("This email is not valid!");

  if (!validator.isStrongPassword(password))
    throw new Error("Kindly choose a stronger password!");

  // UNIQUE EMAIL
  const exists = await this.findOne({ email });

  if (exists) {
    throw new Error("Email already exist!");
  }

  // PASSWORD HASH
  // const salt = await bcrypt.genSalt(12);

  const hash = await bcrypt.hash(this.password, 12);

  const user = await this.create({ email, password: hash });

  return user;
};

// STATIC LOGIN METHOD
userSchema.static.log = async function (email, password) {
  if (!email || !password) throw new Error("Invalid Email and Password");

  const user = await this.findOne({ email });

  if (!user) throw new Error("Incorrect Email");

  const match = await bcrypt.compare(password, user.password);

  if (!match) throw new Error("Incorrect Password");

  return user;
};

const User = mongoose.model("users", userSchema);

module.exports = User;
