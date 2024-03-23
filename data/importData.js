const fs = require("fs");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const Products = require("../models/ProductListModel");
const Blog = require("../models/blogDesignModel");
const Arrivals = require("../models/arrivalModel");
const Features = require("../models/featureProductModel");
const AllFeatures = require("../models/allFeatureModel");
const SummerCollection = require("../models/summerCollectionModel");

dotenv.config({ path: "./server/config.env" });
const DB = process.env.DATABASE.replace(
  "<password>",
  process.env.DATABASE_PASSWORD
);

mongoose
  .connect(DB, {
    useUnifiedTopology: true,
  })
  .then(() => console.log("DB SUCCESSFULLY CONNECTED!!!"));

const products = JSON.parse(
  fs.readFileSync(`${__dirname}/productListData.json`, `utf-8`)
);
const blog = JSON.parse(
  fs.readFileSync(`${__dirname}/blogListData.json`, `utf-8`)
);
const arrivals = JSON.parse(
  fs.readFileSync(`${__dirname}/arrivals.json`, `utf-8`)
);
const features = JSON.parse(
  fs.readFileSync(`${__dirname}/featureProducts.json`, `utf-8`)
);
const allFeatures = JSON.parse(
  fs.readFileSync(`${__dirname}/allFeatures.json`, `utf-8`)
);
const summerCollection = JSON.parse(
  fs.readFileSync(`${__dirname}/summerCollections.json`, `utf-8`)
);

const importData = async function () {
  try {
    await Products.create(products);
    await Blog.create(blog);
    await Arrivals.create(arrivals);
    await Features.create(features);
    await AllFeatures.create(allFeatures);
    await SummerCollection.create(summerCollection);
    console.log("Data successfully imported 😀😎!!!");
  } catch (err) {
    console.log(
      "An Error occured while importing data! Kindly connect to your internet."
    );
  }
  process.exit(1);
};

const deleteData = async function () {
  try {
    await Products.deleteMany();
    await Blog.deleteMany();
    await Arrivals.deleteMany();
    await Features.deleteMany();
    await AllFeatures.deleteMany();
    await SummerCollection.deleteMany();
    console.log("Data successfully deleted ❌🦀!!!");
  } catch (err) {
    console.log(
      "An Error occured while deleting data! Kindly connect to your internet."
    );
  }
  process.exit(1);
};

if (process.argv[2] === "--import") {
  importData();
} else if (process.argv[2] === "--delete") {
  deleteData();
}
