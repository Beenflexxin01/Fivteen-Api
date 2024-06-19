const express = require("express");

const router = express.Router();

const { signupUser, loginUser } = require("../Controllers/userController");

//Login ROute
router.post("/login", loginUser);

//Sign up Route
router.post("/signup", signupUser);

module.exports = router;
