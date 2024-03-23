// const express = require("express");
// const Stripe = require("stripe");
// const { Order } = require("../models/Order");

// const stripe = Stripe(process.env.STRIPE_KEY);
// const router = express.Router();

// require("dotenv").config();

// router.post("/create-checkout-session", async (req, res) => {
//   const customer = await stripe.customers.create({
//     metadata: {
//       userId: req.body.userId,
//       cart: JSON.stringify(req.body.cart),
//     },
//   });
//   const lineItems = req.body.cart.map((item) => {
//     return {
//       price_data: {
//         // currency: "usd",
//         product_data: {
//           name: item.title,
//           images: [item.image],
//           metadata: {
//             id: item.id,
//           },
//         },
//         unit_amount: item.price * 100,
//       },

//       quantity: item.quantity,
//     };
//   });

//   const session = await stripe.checkout.sessions.create({
//     payment_method_types: ["card"],
//     shipping_address_collection: {
//       allowed_countries: ["US", "CA", "NG"],
//     },
//     phone_number_collection: {
//       enabled: true,
//     },
//     customer: customer.id,
//     lineItems,
//     mode: "payment",
//     success_url: `${process.env.CLIENT_URL}/checkout-success`,
//     cancel_url: `${process.env.CLIENT_URL}/Home`,
//   });

//   res.send({ url: session.url });
// });

// // Create Order
// const createOrder = async (customer, data) => {
//   const items = JSON.parse(customer.metadata.cart);

//   const newOrder = new Order({
//     userId: customer.metadata.userId,
//     customerId: data.customer,
//     paymentIntentId: data.payment_intent,
//     products: items,
//     subTotal: data.price_subtotal,
//     total: data.price_total,
//     shipping: data.customer_details,
//     payment_status: data.payment_status,
//   });
//   try {
//     const savedOrder = await newOrder.save();

//     console.log("Order Successfully Processed", savedOrder);
//   } catch (err) {
//     console.log(err.message);
//   }
// };
// // Stripe webhook
// // This is your Stripe CLI webhook secret for testing your endpoint locally.
// let endpointSecret;

// // endpointSecret =
// //   "whsec_9028b109a4f2c88eab09d50aee40f4a253e3a78d7054d62523508a49794045a0";

// router.post(
//   "/webhook",
//   express.raw({ type: "application/json" }),
//   (request, response) => {
//     const sig = request.headers["stripe-signature"];

//     let data;
//     let eventType;

//     if (endpointSecret) {
//       let event;

//       try {
//         event = stripe.webhooks.constructEvent(
//           request.body,
//           sig,
//           endpointSecret
//         );
//         console.log("WEBHOOK VERIFIED!!");
//       } catch (err) {
//         CONSOLE.LOG("WEBHOOK ERROR");
//         response.status(400).send(`Webhook Error: ${err.message}`);
//         return;
//       }
//       data = event.data.object;
//       eventType = event.type;
//     } else {
//       data = req.body.data.object;
//       eventType = req.body.type;
//     }

//     // Handle the event
//     // switch (event.type) {
//     //   case "payment_intent.succeeded":
//     //     const paymentIntentSucceeded = event.data.object;
//     //     // Then define and call a function to handle the event payment_intent.succeeded
//     //     break;
//     //   // ... handle other event types
//     //   default:
//     //     console.log(`Unhandled event type ${event.type}`);
//     // }
//     // Return a 200 response to acknowledge receipt of the event
//     if (eventType === "checkout.session.asyc_payment_succeeded") {
//       stripe.customers
//         .retrieve(data.customer)
//         .then((customer) => {
//           createOrder(customer, data);
//         })
//         .catch((err) => console.log(err.message));
//     }
//     response.send().end();
//   }
// );

// // app.listen(4242, () => console.log('Running on port 4242'));

// module.exports = router;
