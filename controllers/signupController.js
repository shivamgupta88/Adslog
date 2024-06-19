const express = require("express");
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const axios = require("axios");
const signupRouter = require("../routes/signupRoutes");
const crypto = require('crypto');

// redis
const client = require("../redis/client.js");
const { PrismaClient, Prisma } = require("@prisma/client");
const { log } = require("console");
const { ClientRequest } = require("http");
const e = require("express");

const prisma = new PrismaClient();
const app = express();

app.use(bodyParser.json());

exports.signup = async (req, res) => {
  const {
    password,
    account_type,
    first_name,
    last_name,
    country_of_residence,
    city,
    address,
    email,
    messenger,
    website,
    daily_traffic_amount,
    phone_no,
  } = req.body;

  try {
    // Check if email already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(400).json({ error: "Email already exists" });
    }

    let testAccount = await nodemailer.createTestAccount();
    // connect with the smtp
    let transporter = nodemailer.createTransport({
      host: "smtp.ethereal.email",
      port: 587,
      auth: {
        user: "iliana.kovacek@ethereal.email",
        pass: "mQvYZQwfBk7QsFfz9T",
      },
    });

    const userId = uuidv4(); // Replace with actual user ID or token

    console.log("userId is ", userId);

    const mail = "shivamgupta5354@gmail.com";
    let info = await transporter.sendMail({
      from: '"Etty man" <iliana.kovacek@ethereal.email>', // sender address
      to: mail, // list of receivers
      subject: "Click Link to verify email Id.", // Subject line
      text: "Verify your email", // plain text body
      html: `<b>Hello </b><br><a href="http://localhost:3000/api/verify/${email}">Click here to verify</a>`, // html body with verification link
    });

    console.log("Message sent: %s", info.messageId);
    // res.json(info);

    // Check if phone number already exists
    const existingPhone = await prisma.user.findUnique({
      where: { phone_no },
    });

    if (existingPhone) {
      return res.status(400).json({ error: "Phone number already exists" });
    }

    // Generate random OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log("Your OTP for phone verification is ", otp);

    // Store phone number with OTP in the database
    // await prisma.otp.upsert({
    //   where: { phone_no },
    //   update: { otp },
    //   create: { phone_no, otp },
    // });

    async function hashPassword(password) {
      const salt_string = crypto.randomBytes(16).toString("hex");
      const saltedPassword = password + salt_string;
      const hashed_password = await bcrypt.hash(saltedPassword, 10);

      

      return { hashed_password, salt_string };
    }

    const {hashed_password ,salt_string } = await hashPassword(password);

    console.log("hashed pas is " , hashed_password)
    console.log("saltstring is " , salt_string)
    const storedPassword = await prisma.password.create({
      data: {
          user_id: email,  // Assuming you want to generate a unique userId
          salt_string : salt_string,
          hashed_password : hashed_password
      }
  });

    const newUser = await prisma.user.create({
      data: {
        // password: hashedPassword,
        account_type,
        first_name,
        last_name,
        country_of_residence,
        city,
        address,
        email, // You can still store email for future verification if needed
        messenger,
        website,
        daily_traffic_amount,
        verified_status: false, // Consider adding a verification process later
        phone_no,
        phone_no_verified_status: false,
      },
    });

    // const newPassword = await prisma.password.create({
    //   data: {
    //     password: password,
    //     user_id: email,
    //   },
    // });

    res.status(201).json({
      message: "User created successfully. Phone number and OTP inserted.",
      user: {
        user_id: newUser.user_id,
        account_type,
        first_name,
        last_name,
        country_of_residence,
        city,
        address,
        email,
        messenger,
        website,
        daily_traffic_amount,
        phone_no,
      },
    });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Error creating user" });
  }
};

exports.verifyOpt = async (req, res) => {
  const { phone_no, otp } = req.body;

  try {
    // Find the OTP record for the given phone number
    const otpRecord = await prisma.otp.findUnique({
      where: {
        phone_no,
      },
    });

    if (!otpRecord) {
      return res.status(400).json({ error: "Phone number not found" });
    }

    // Check if the OTP matches
    if (otpRecord.otp !== otp) {
      return res.status(400).json({ error: "Invalid OTP" });
    }

    // Update the user's phone number verification status
    await prisma.user.update({
      where: {
        phone_no,
      },
      data: {
        phone_no_verified_status: true,
      },
    });

    // Optionally, delete the OTP record after verification
    await prisma.otp.delete({
      where: {
        phone_no,
      },
    });

    res.status(200).json({ message: "Phone number verified successfully" });
  } catch (error) {
    console.error("Error verifying OTP:", error);
    res.status(500).json({ error: "Error verifying OTP" });
  }
};

exports.loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });
    if (user.verified_status === false) {
      return res.status(404).json({ error: "Please verify your account" });
    }
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if the password matches
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        userId: user.user_id,
        email: user.email,
      },
      "your_secret_key", // Replace with your actual secret key for JWT
      {
        expiresIn: "1h", // Token expiration time
      }
    );

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ error: "Error logging in" });
  }
};

// add a Website
exports.addwebsite = async (req, res) => {
  try {
    // Extract user_id from headers
    const user_id = req.headers.userid;

    if (!user_id) {
      return res.status(400).json({ error: "User ID is required in headers" });
    }

    const { name, domain, email, password } = req.body;

    const website_id = uuidv4();
    const share_id = uuidv4();

    const newWebsite = await prisma.website.create({
      data: {
        website_id,
        name,
        domain,
        user_id, // Correct assignment of user_id
        share_id,
      },
    });

    // login the user in umami to get token  use username and password
    // use the token to inset website detials in umami

    async function login() {
      const usertoken = await client.get(user_id);
      if (usertoken) {
        console.log("cache token is ", usertoken);
        return usertoken;
      }
      try {
        console.log("password is ", password);
        console.log("email is ", email);

        const response = await axios.post(
          "http://localhost:3000/api/auth/login",
          {
            username: email,
            password: password,
          }
        );
        await client.set(user_id, response.data.token);
        await client.expire(user_id, 60);
        return res.json(response.data.token);
        // return response.data.token;
      } catch (error) {
        console.error("Error during user loggin in adding website:", error);
        throw error; // Propagate the error if necessary
      }
    }
    async function addWebsite(token) {
      try {
        const response = await axios.post(
          "http://localhost:3000/api/websites",
          {
            name: name,
            domain: domain,
            username: email,
          },
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );
        console.log("Website added successfully:", response.data);
      } catch (error) {
        if (error.response) {
          // The request was made and the server responded with a status code
          console.error("Error status code:", error.response.status);
          console.error("Error response data:", error.response.data);
        } else if (error.request) {
          // The request was made but no response was received
          console.error("No response received:", error.request);
        } else {
          // Something happened in setting up the request that triggered an Error
          console.error("Error setting up request:", error.message);
        }
        throw error; // Propagate the error if necessary
      }
    }

    (async () => {
      try {
        const loginToken = await login(email, password, email);
        console.log("loginToken is", loginToken);
        await addWebsite(loginToken);
      } catch (error) {
        console.error("An error occurred:", error);
      }
    })();

    res.status(200).json({ message: " creating website successfull" });
  } catch (error) {
    console.error("Error creating website:", error);
    res.status(500).json({ error: "Error creating website" });
  }
};

exports.verifyEmail = async (req, res) => {
  let dataToSend;
  const userId = req.headers["user-id"];
  const email = req.params.mail;
  console.log(`Verification link clicked by user`);

  const emailRecord = await prisma.user.findUnique({
    where: {
      email,
    },
  });
  console.log("emailRecord is", JSON.stringify(emailRecord));
  // dataToSend = JSON.stringify(emailRecord) ;
  dataToSend = emailRecord;
  if (!emailRecord) {
    return res.status(400).json({ error: "email not found" });
  }

  // Update the user's phone number verification status
  await prisma.user.update({
    where: {
      email,
    },
    data: {
      verified_status: true,
    },
  });

  // Now create user in umami

  // 1. login the admin  to get tokenn
  // Declare dataToSend globally

  async function login() {
    const cacheAdminToken = await client.get("adminToken");
    if (cacheAdminToken) {
      console.log("cahcke is ", cacheAdminToken);
      return cacheAdminToken;
    }
    try {
      const response = await axios.post(
        "http://localhost:3000/api/auth/login",
        {
          username: "admin", // Replace with your actual username
          password: "umami", // Replace with your actual password
        }
      );

      await client.set("adminToken", response.data.token);
      await client.expire("adminToken", 60 * 60);
      return res.json(response.data.token);

      // return response.data.token; // Assuming the token is returned in a field named 'token'
    } catch (error) {
      console.error("Error during login:", error);
      throw error; // Propagate the error if necessary
    }
  }

  async function fetchData(token) {
    console.log("dataTosend is ", dataToSend);
    const data = {
      username: dataToSend.email,
      // password: dataToSend.password,
      role: "user",
      account_type: "Individual",
    };

    console.log("data is ", data);

    try {
      const response = await axios.post(
        "http://localhost:3000/api/users",
        data,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
      console.log("User created successfully:", response.data);
      // store password

      const pass = dataToSend.password;
    } catch (error) {
      console.error("Error fetching data:", error);
      throw error; // Propagate the error if necessary
    }

    // Insert the data in umimo
  }

  // Call login and then fetchData
  login()
    .then((token) => fetchData(token))
    .catch((error) => console.error("Error:", error));

  res.send("Email verified successfully!");
};
