const mongoose = require("mongoose");

const productOverviewSchema = new mongoose.Schema({
  title: String,
  price: Number,
  image: String,
  productId: Number,
  quantity: Number,
  sale: Number,
  revenue: Number,
  status: String,
});

const ProductOverview = mongoose.model(
  "productOverview",
  productOverviewSchema
);

module.exports = ProductOverview;
