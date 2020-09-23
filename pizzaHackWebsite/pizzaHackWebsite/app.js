const express = require("express");
const bodyParser = require("body-parser");
const request = require("request");
const app = express();
const fs = require("fs");
app.use(express.static(__dirname + "/public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.get("/", function (req, res) {
  res.sendFile(__dirname + "/index.html");
});

app.post("/", function (req, res) {
  console.log("index : req.body", req.body);
  res.sendFile("hacked.html");
});
app.listen("3000", function (req, res) {
  console.log("listenning on port 3000");
});
