const express = require("express");

const router = express.Router();
const stripeController = require("../stripeController");
// const getSuccess = require("../stripeController");
require("dotenv").config();

router.get("/create-checkout-session", stripeController.getCheckOutSession);
// router.get("/getSuccess", stripeController.getCheckOutSession);
// router.get("/getFailure", stripeController.getCheckOutSession);

module.exports = router;

// This is your test secret API key.
// const stripe = require('stripe')('sk_test_51Odt2FDmPNeUOkUZxCwTCRIJGYwVXFAz8UAWARZb0YxYwoZ03uu98KfbGPcj7GcR9Nwkn5Az2DRgZfZPnSsfUV7K00xU1ZdT2P');
// const express = require('express');
// const app = express();
// app.use(express.static('public'));

// const YOUR_DOMAIN = 'http://localhost:4242';

// app.post('/create-checkout-session', async (req, res) => {
//   const session = await stripe.checkout.sessions.create({
//     line_items: [
//       {
//         // Provide the exact Price ID (for example, pr_1234) of the product you want to sell
//         price: '{{PRICE_ID}}',
//         quantity: 1,
//       },
//     ],
//     mode: 'payment',
//     success_url: `${YOUR_DOMAIN}?success=true`,
//     cancel_url: `${YOUR_DOMAIN}?canceled=true`,
//   });

//   res.redirect(303, session.url);
// });

// app.listen(4242, () => console.log('Running on port 4242'));
