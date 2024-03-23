const mongoose = require("mongoose");

const featureSchema = new mongoose.Schema({
  title: String,
  default: String,
  price: Number,
  oldPrice: String,
  image: String,
  imageCover: [String],
  description: String,
  size: String,
  sale: String,
  paymentOption: String,
  shipPrice: String,
  quantity: String,
  qtnNum: Number,
  qtnBtn: String,
  qtnBtnAdd: String,
  color: String,
  cart: String,
  buy: String,
  btnPay: String,
  btnPal: String,
  soldOut: String,
});

const AllFeatures = mongoose.model("allFeatures", featureSchema);

module.exports = AllFeatures;
