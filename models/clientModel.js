const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const clientSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "A user must have a name"],
    trim: true,
  },
  email: {
    type: String,
    required: [true, "A user must have an activ email address!"],
    unique: true,
    lowercase: true,
    validator: [
      validator.isEmail,
      "The stated email string must be a valid email address",
    ],
  },

  photo: {
    type: String,
    default: "",
  },

  password: {
    type: String,
    required: [true, "A user must have a unique password"],
    minlength: [8, "A password must not be less than 8 characters"],
    select: false,
  },

  role: {
    type: String,
    enum: ["user", "guide", "lead-guide", "admin"],
    default: "user",
  },
});

clientSchema.pre("save", async (next) => {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 12);

  next();
});

clientSchema.pre("save", (next) => {
  if (!this.isModified("password" || this.isNew)) return next();

  this.passwordChangedAt = Date.now() - 1000;

  next();
});

clientSchema.methods.correctPassword = async (
  candidatePassword,
  userPassword
) => {
  return await bcrypt.compare(candidatePassword, userPassword);
};

clientSchema.methods.changePasswordAfter = (JWTTimeStamp) => {
  if (this.passwordChangedAt) {
    const changeTimeStamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimeStamp < changeTimeStamp;
  }
  return false;
};

clientSchema.createPasswordResetToken = () => {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.passwordResetExpired = Date.now() * 10 * 10 * 1000;
};

const Clients = mongoose.model("clients", clientSchema);

module.exports = Clients;
