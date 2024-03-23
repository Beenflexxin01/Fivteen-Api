const mongoose = require("mongoose");
const path = require("path");
const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const Products = require("./models/ProductListModel");
const Arrivals = require("./models/arrivalModel");
const Blog = require("./models/blogDesignModel");
const Features = require("./models/featureProductModel");
const AllFeatures = require("./models/allFeatureModel");
const SummerCollection = require("./models/summerCollectionModel");
const compression = require("compression");
const stripe = require("./Routes/stripe");
const app = express();

app.use(express.json());
app.use(
  cors({
    credentials: true,
    origin: "http://localhost:5173",
    // origin: "https://fiveteen-studios.onrender.com",
  })
);

// app.use("api/stripe", stripe);
app.use("api/create-checkout-session", stripe);

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
  console.log(err.name);
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

app.get("/api/blogs", async (req, res) => {
  try {
    const blogs = await Blog.find();
    res.json(blogs);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.get("/api/blogs/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const blogs = await Blog.findById(id);
    res.json(blogs);
  } catch (error) {
    console.error(error);
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

app.use(compression());

process.on("SIGTERM", function () {
  console.log("🤗 SIGTERM RECEIVED, Shutting down gracefully");
  server.close(function () {
    console.log("🔥 Process Terminated");
  });
});
