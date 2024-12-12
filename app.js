const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const User = require("./models/model.js"); // Import User directly
const dotenv = require("dotenv");
const cors = require("cors");

const jwt = require("jsonwebtoken");
dotenv.config(); // Load environment variables from .env file

const app = express();
app.use(express.json());
app.use(cors());
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("db connection success");
    app.listen(3000, () => {
      console.log("Server is running on port 3000");
    });
  } catch (error) {
    console.error("db connection error:", error);
    process.exit(1); // Exit process with failure
  }
};

connectDB();

app.get("/", (req, res) => {
  res.send("hello world");
});

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const isUserExist = await User.findOne({ username });

    if (!isUserExist) {
      if (password.length < 5) {
        return res.status(400).send("Password is too short");
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = await User.create({ username, password: hashedPassword });
      return res.status(201).send(user);
    } else {
      return res.status(400).send("User already exists");
    }
  } catch (error) {
    return res.status(500).send({ error: "Failed to register user" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const dbUser = await User.findOne({ username });
  if (!dbUser) {
    return res.status(400).send("Invalid user");
  }
  const isPasswordEqual = await bcrypt.compare(password, dbUser.password);
  if (isPasswordEqual) {
    const payload = { username };
    const jwtToken = jwt.sign(payload, "secret_token");
    return res.status(200).send({ jwt_token: jwtToken });
  } else {
    return res.status(400).send("Invalid password");
  }
});

app.put("/change-password", async (request, response) => {
  try {
    const { username, oldPassword, newPassword } = request.body;
    const dbUser = await User.findOne({ username });

    if (!dbUser) {
      return response.status(400).send("Invalid User");
    }
    const isPasswordEqual = await bcrypt.compare(oldPassword, dbUser.password);
    if (!isPasswordEqual) {
      return response.status(400).send("Invalid current password");
    }
    if (newPassword.length < 5) {
      return response.status(400).send("Password is too short");
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.updateOne({ username }, { password: hashedPassword });
    return response.status(200).send("Password updated");
  } catch (error) {
    return response.status(500).send({ error: "Failed to update password" });
  }
});

app.get("/users", async (request, response) => {
  const users = await User.find({});
  response.send(users);
});
