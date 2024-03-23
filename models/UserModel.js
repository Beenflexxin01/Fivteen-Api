const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, minlength: 3 },
    enail: {
      type: String,
      minlength: 3,
      required: true,
      unique: true,
    },
    password: { type: String, required: true, minlength: 3, maxlength: 20 },
    isVerified: { type: Boolean, default: false },
    emailToken: { type: String },
  },
  { timestamps: true }
);

const User = mongoose.model("user", userSchema);

module.exports = User;
