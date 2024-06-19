const User = require("../models/UserModel");
const jwt = require("jsonwebtoken");

const createToken = (_id) => {
  return jwt.sign({ _id }, process.env.JWT_SECRET, { expiresIn: "4d" });
};

//Login User
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.login(email, password);

    //   Create token
    const token = createToken(user._id);

    res.status(200).json({ email, token });
  } catch (err) {
    console.log(err);
    res.status(400).json(err.message);
  }
};

//Signup User
const signupUser = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.signup(email, password);
    // const user = await User.create({
    //   name: req.body.name,
    //   email: req.body.email,
    //   password: req.body.password,
    // });

    const token = createToken(user._id);
    res.status(200).json({ email, token });
  } catch (err) {
    console.log(err);
    res.status(400).json(err.message);
  }
};

module.exports = { signupUser, loginUser };
