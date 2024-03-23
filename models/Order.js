const mongoose = require("mongoose");

const orderSchema = new mongoose.Schema(
  {
    userId: { type: String, require: true },
    customerId: { type: String },
    paymentIntentId: { type: String },

    products: [
      {
        Id: { type: String },
        title: { type: String },
        description: { type: String },
        price: { type: String },
        image: { type: String },
        quantity: { type: Number },
      },
    ],
    subTotal: { type: Number, required: true },
    Total: { type: Number, required: true },
    shipping: { type: Object, required: true },
    delivery_status: { type: String, default: 'pending' },
    paymnet_status: { type: String, required: true },
  },
  { timestamps: true }
);

const Order = mongoose.model("Order", orderSchema);

exports.Order = Order;
