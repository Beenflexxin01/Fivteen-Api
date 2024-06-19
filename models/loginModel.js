const mongoose = require("mongoose");
const validator = require("validator");
const loginSchema = new mongoose.Schema({
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

  password: {
    type: String,
    required: [true, "A user must have a unique password"],
    minlength: [8, "A password must not be less than 8 characters"],
    select: false,
  },
});

loginSchema.pre("save", async (next) => {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 12);

  next();
});

loginSchema.pre("save", (next) => {
  if (!this.isModified("password" || this.isNew)) return next();

  this.passwordChangedAt = Date.now() - 1000;

  next();
});

loginSchema.methods.correctPassword = async (
  candidatePassword,
  userPassword
) => {
  return await bcrypt.compare(candidatePassword, userPassword);
};

loginSchema.methods.changePasswordAfter = (JWTTimeStamp) => {
  if (this.passwordChangedAt) {
    const changeTimeStamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimeStamp < changeTimeStamp;
  }
  return false;
};

loginSchema.createPasswordResetToken = () => {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.passwordResetExpired = Date.now() * 10 * 10 * 1000;
};

const Login = mongoose.model("logins", loginSchema);

module.exports = Login;
