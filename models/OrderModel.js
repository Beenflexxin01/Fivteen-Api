const mongoose = require("mongoose");

const orderSchema = new mongoose.Schema({
  title: String,
  amount: Number,
  image: String,
  productId: Number,
  status: String,
});

const Orders = mongoose.model("orders", orderSchema);

module.exports = Orders;
