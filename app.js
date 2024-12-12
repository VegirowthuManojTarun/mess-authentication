const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cors = require("cors");

const Student = require("./models/student.js");
const Faculty = require("./models/faculty.js");
const validateEmailDomain = require("./middlewares/validateEmailDomain");

dotenv.config(); // Load environment variables

const app = express();
app.use(express.json());
app.use(cors());

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("Database connection successful");
    app.listen(3000, () => {
      console.log("Server is running on port 3000");
    });
  } catch (error) {
    console.error("Database connection error:", error);
    process.exit(1);
  }
};

connectDB();

const generateToken = (payload) => jwt.sign(payload, process.env.SECRET_TOKEN);

const validateRequestBody = (requiredFields) => (req, res, next) => {
  const missingFields = requiredFields.filter((field) => !req.body[field]);
  if (missingFields.length) {
    return res.status(400).send({
      isSuccess: false,
      message: `Missing required fields: ${missingFields.join(", ")}`,
    });
  }
  next();
};

const validatePosition = (email) => {
  const position = email.split("@")[0];
  const allowedUsernames = ["ao", "dean", "ada", "dsw"];
  return allowedUsernames.includes(position);
};

app.get("/", (req, res) => {
  res.send("Hello, World!");
});

// Student Registration
app.post(
  "/student/register",
  validateEmailDomain,
  validateRequestBody(["email", "password", "userName"]),
  async (req, res) => {
    try {
      const { email, password, userName, isRepresentative } = req.body;

      if (await Student.findOne({ email })) {
        return res.status(400).send({
          isSuccess: false,
          message: "Student email is already registered",
        });
      }

      if (password.length < 8) {
        return res.status(400).send({
          isSuccess: false,
          message: "Password is too short",
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const newStudent = await Student.create({
        email,
        userName,
        password: hashedPassword,
        isRepresentative,
      });

      return res.status(201).send({
        isSuccess: true,
        message: "Student registration successful",
      });
    } catch (error) {
      console.error("Error while registering student:", error);
      return res.status(500).send({
        isSuccess: false,
        message: "Failed to register student",
      });
    }
  }
);

// Student Login
app.post(
  "/student/login",
  validateRequestBody(["email", "password"]),
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const student = await Student.findOne({ email });

      if (!student) {
        return res.status(400).send({
          isSuccess: false,
          message: "Invalid student email",
        });
      }

      const isPasswordValid = await bcrypt.compare(password, student.password);

      if (!isPasswordValid) {
        return res.status(400).send({
          isSuccess: false,
          message: "Invalid password",
        });
      }

      const token = generateToken({ email });

      return res.status(200).send({
        isSuccess: true,
        message: "Student login successful",
        jwtToken: token,
      });
    } catch (error) {
      console.error("Error during student login:", error);
      return res.status(500).send({
        isSuccess: false,
        message: "Login failed",
      });
    }
  }
);

// Faculty Registration
app.post(
  "/faculty/register",
  validateEmailDomain,
  validateRequestBody(["email", "password", "userName"]),
  async (req, res) => {
    try {
      const { email, password, userName } = req.body;

      if (!validatePosition(email)) {
        return res.status(400).send({
          isSuccess: false,
          message: "Invalid faculty email",
        });
      }

      if (await Faculty.findOne({ email })) {
        return res.status(400).send({
          isSuccess: false,
          message: "Faculty email already registered",
        });
      }

      if (password.length < 8) {
        return res.status(400).send({
          isSuccess: false,
          message: "Password is too short",
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const newFaculty = await Faculty.create({
        email,
        userName,
        password: hashedPassword,
        position: email.split("@")[0],
      });

      return res.status(201).send({
        isSuccess: true,
        message: "Faculty registration successful",
      });
    } catch (error) {
      console.error("Error while registering faculty:", error);
      return res.status(500).send({
        isSuccess: false,
        message: "Failed to register faculty",
      });
    }
  }
);

// Faculty Login
app.post(
  "/faculty/login",
  validateRequestBody(["email", "password"]),
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const faculty = await Faculty.findOne({ email });

      if (!faculty) {
        return res.status(400).send({
          isSuccess: false,
          message: "Invalid faculty email",
        });
      }

      const isPasswordValid = await bcrypt.compare(password, faculty.password);

      if (!isPasswordValid) {
        return res.status(400).send({
          isSuccess: false,
          message: "Invalid password",
        });
      }

      const token = generateToken({ email });

      return res.status(200).send({
        isSuccess: true,
        message: "Faculty login successful",
        jwtToken: token,
      });
    } catch (error) {
      console.error("Error during faculty login:", error);
      return res.status(500).send({
        isSuccess: false,
        message: "Login failed",
      });
    }
  }
);

//representative login check
app.post(
  "/representative/login",
  validateRequestBody(["email", "password"]),
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const student = await Student.findOne({ email });

      if (!student) {
        return res.status(400).send({
          isSuccess: false,
          message: "Invalid student representative email",
        });
      }

      // Check if the student is registered as a representative
      if (!student.isRepresentative) {
        return res.status(400).send({
          isSuccess: false,
          message: "Student email is not registered as a representative email",
        });
      }

      const isPasswordValid = await bcrypt.compare(password, student.password);

      if (!isPasswordValid) {
        return res.status(400).send({
          isSuccess: false,
          message: "Invalid password",
        });
      }

      const token = generateToken({ email });

      return res.status(200).send({
        isSuccess: true,
        message: "Representative login successful",
        jwtToken: token,
      });
    } catch (error) {
      console.error("Error during representative login:", error);
      return res.status(500).send({
        isSuccess: false,
        message: "Login failed",
      });
    }
  }
);

// Password Change (Reusable Logic)
const changePassword = async (req, res, Model) => {
  try {
    const { email, oldPassword, newPassword } = req.body;

    const user = await Model.findOne({ email });

    if (!user) {
      return res.status(400).send({
        isSuccess: false,
        message: "Invalid email",
      });
    }

    if (!(await bcrypt.compare(oldPassword, user.password))) {
      return res.status(400).send({
        isSuccess: false,
        message: "Invalid current password",
      });
    }

    if (await bcrypt.compare(newPassword, user.password)) {
      return res.status(400).send({
        isSuccess: false,
        message: "New password cannot be the same as the current password",
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).send({
        isSuccess: false,
        message: "New password is too short",
      });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    return res.status(200).send({
      isSuccess: true,
      message: "Password updated successfully",
    });
  } catch (error) {
    console.error("Error updating password:", error);
    return res.status(500).send({
      isSuccess: false,
      message: "Failed to update password",
    });
  }
};

app.put("/student/change-password", (req, res) =>
  changePassword(req, res, Student)
);
app.put("/faculty/change-password", (req, res) =>
  changePassword(req, res, Faculty)
);

app.get("/students", async (req, res) => {
  try {
    const students = await Student.find({});
    res.status(200).send(students);
  } catch (error) {
    console.error("Error fetching students:", error);
    res.status(500).send({
      isSuccess: false,
      message: "Failed to fetch students",
    });
  }
});
