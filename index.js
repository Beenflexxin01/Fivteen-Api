// const stripe = require("stripe")(process.env.STRIPE_SECRET_NUMBER);
const stripe = require("stripe")(
  "sk_test_51Odt2FDmPNeUOkUZxCwTCRIJGYwVXFAz8UAWARZb0YxYwoZ03uu98KfbGPcj7GcR9Nwkn5Az2DRgZfZPnSsfUV7K00xU1ZdT2P"
);
const mongoose = require("mongoose");
const path = require("path");
const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const Products = require("./models/ProductListModel");
const Arrivals = require("./models/arrivalModel");
const Features = require("./models/featureProductModel");
const AllFeatures = require("./models/allFeatureModel");
const SummerCollection = require("./models/summerCollectionModel");
const Clients = require("./models/clientModel");
const compression = require("compression");
// const stripe = require("./Routes/stripe");
const uuid = require("uuid");

const ProductOverview = require("./models/ProductOverviewModel");
const Orders = require("./models/OrderModel");
const Login = require("./models/loginModel");

const userRoutes = require("./Routes/UsersRoute");
const app = express();

app.use(express.json());
app.use(
  cors({
    credentials: true,
    origin: "http://localhost:5173",
    methods: ["GET", "POST", "PUT", "DELETE"],
    // origin: "https://fiveteen-studios.onrender.com",
  })
);

app.options("*", cors());

app.post("/api/create-checkout-session", async (req, res) => {
  const { product } = req.body;

  const line_items = product.map((product) => {
    return {
      price_data: {
        currency: "usd",
        // customer: customer.id,

        product_data: {
          name: product.title,
          images: [product.image],
          metadata: {
            id: product.id,
          },
        },
        unit_amount: Math.round(product.price * 100),
      },

      quantity: product.quantity,
    };
  });

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    shipping_address_collection: {
      allowed_countries: ["US", "CA", "NG"],
    },
    phone_number_collection: {
      enabled: true,
    },
    line_items,
    mode: "payment",
    // success_url: "http://localhost:5173/products",
    // cancel_url: "http://localhost:5173/home",
    success_url: "https://fivteen-api.vercel.app/order/success",
  });

  res.send({ url: session.url });
});

app.get("/order/success", async (req, res) => {
  const session = await stripe.checkout.sessions.retrieve(req.query.session_id);
  const customer = await stripe.customers.retrieve(session.customer);

  res.send(
    `<html><body><h1>Thanks for your order, ${customer.name}!</h1></body></html>`
  );
});

// app.post("/api/payment", (req, res) => {
//   const { product, token } = req.body;

//   console.log("PRODUCT", product);
//   console.log("PRICE", product.price);

//   const itempotencyKey = uuid();

//   return stripe.customers
//     .create({
//       email: token.email,
//       source: token.id,
//     })
//     .then((customer) => {
//       stripe.charges.create(
//         {
//           amount: product.price * 100,
//           currency: "usd",
//           customer: customer.id,
//           receipt_email: token.email,
//           description: `purchase of ${product.name}`,
//           shipping: {
//             name: token.card.name,
//             address: {
//               country: token.card.address_country,
//             },
//           },
//         },
//         { itempotencyKey }
//       );
//     })
//     .then((result) => res.status(200).json(result))
//     .catch((err) => {
//       console.log(err);
//     });
// });

// app.use("api/stripe", stripe);
// app.use("api/create-checkout-session", stripe);

process.on("UncaughtException", (err) => {
  console.log(err.message);
  console.log("UNCAUGHT EXCEPTION... SHUTTING DOWN NOW......");
});

// dotenv.config({ path: "./config.env" });
dotenv.config({ path: "./server/config.env" });

const DB = process.env.DATABASE.replace(
  "<password>",
  process.env.DATABASE_PASSWORD
);

mongoose
  .connect(DB, {
    useNewUrlParser: true,
  })
  .then(() => console.log("DB CONNECTION SUCCESSFUL 😉😎!"));

const port = process.env.PORT || 8000;

const server = app.listen(port, () =>
  console.log(`App is running on port ${port}`)
);

process.on("unhandledRejection", (err) => {
  console.log(err.message);
  console.log("UNHANDLED REJECTION! KINDLY CONNECT TO THE INTERNET😑");
  server.close(() => process.exit(1));
});

app.get("/api/products", async (req, res) => {
  try {
    const products = await Products.find();
    res.json(products);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.get("/api/arrivals", async (req, res) => {
  try {
    const arrivals = await Arrivals.find();
    res.json(arrivals);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.get("/api/arrivals/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const arrivals = await Arrivals.findById(id);
    res.json(arrivals);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const products = await Products.findById(id);
    res.json(products);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.get("/api/features", async (req, res) => {
  try {
    const features = await Features.find();
    res.json(features);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.get("/api/features/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const features = await Features.findById(id);
    res.json(features);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.get("/api/productOverview", async (req, res) => {
  try {
    const productOverview = await ProductOverview.find();

    res.json(productOverview);
  } catch (err) {
    console.log(err);
    res.status(500).send("Server Error");
  }
});

app.get("/api/orders", async (req, res) => {
  try {
    const orders = await Orders.find();

    res.json(orders);
  } catch (err) {
    console.log(err);
    res.status(500).send("Server Error");
  }
});

app.get("/api/allfeatures", async (req, res) => {
  try {
    const allFeature = await AllFeatures.find();
    res.json(allFeature);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.get("/api/allfeatures/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const allFeature = await AllFeatures.findById(id);
    res.json(allFeature);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.get("/api/summer", async (req, res) => {
  try {
    const summerCollection = await SummerCollection.find();
    res.json(summerCollection);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.get("/api/summer/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const summerCollection = await SummerCollection.findById(id);
    res.json(summerCollection);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.use("/api/user", userRoutes);

app.use(compression());

process.on("SIGTERM", function () {
  console.log("🤗 SIGTERM RECEIVED, Shutting down gracefully");
  server.close(function () {
    console.log("🔥 Process Terminated");
  });
});
