const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const nodemailer = require('nodemailer');
const axios = require('axios');
const signupRouter = require("./routes/signupRoutes")

const { PrismaClient, Prisma } = require("@prisma/client");

const jwt = require("jsonwebtoken");
const prisma = new PrismaClient();
const app = express();
app.use(bodyParser.json());
app.use('/api', signupRouter) ; 

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

