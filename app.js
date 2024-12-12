const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const Student = require("./models/student.js"); // Import Student directly
const Faculty = require("./models/faculty.js");
const dotenv = require("dotenv");
const cors = require("cors");
const validateEmailDomain = require("./middlewares/validateEmailDomain"); // Import the middleware

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

//student sign-up
app.post("/student/register", validateEmailDomain, async (req, res) => {
  try {
    const { email, password, userName, isRepresentative } = req.body;

    const isStudentExist = await Student.findOne({ email });
    if (isStudentExist) {
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

    console.log(newStudent);
    return res.status(201).send({
      isSuccess: true,
      message: "Student email registration is successful",
    });
  } catch (error) {
    console.error("Error while registering student:", error);
    return res.status(500).send({
      isSuccess: false,
      message: "Failed to register student",
    });
  }
});

//student sign-in
app.post("/student/login", async (req, res) => {
  const { email, password } = req.body;
  const dbEmail = await Student.findOne({ email });
  if (!dbEmail) {
    return res.status(400).send({
      isSuccess: false,
      message: "Invalid student email",
    });
  }
  const isPasswordEqual = await bcrypt.compare(password, dbEmail.password);
  if (isPasswordEqual) {
    const payload = { email };
    const jwtToken = jwt.sign(payload, "secret_token");
    return res.status(200).send({
      isSuccess: true,
      message: "Student login successful",
      jwt_token: jwtToken,
    });
  } else {
    return res.status(400).send({
      isSuccess: false,
      message: "Invalid password",
    });
  }
});

//representative login check
app.post("/representative/login", async (req, res) => {
  const { email, password } = req.body;
  const dbEmail = await Student.findOne({ email });
  const { isRepresentative } = dbEmail;
  console.log(isRepresentative);
  if (!dbEmail) {
    return res.status(400).send({
      isSuccess: false,
      message: "Invalid student representative email",
    });
  }
  if (!isRepresentative) {
    return res.status(400).send({
      isSuccess: false,
      message: "Student email is not registered as representative email",
    });
  }
  const isPasswordEqual = await bcrypt.compare(password, dbEmail.password);
  if (isPasswordEqual) {
    const payload = { email };
    const jwtToken = jwt.sign(payload, "secret_token");
    return res.status(200).send({
      isSuccess: true,
      message: "Representative login successful",
      jwt_token: jwtToken,
    });
  } else {
    return res.status(400).send({
      isSuccess: false,
      message: "Invalid password",
    });
  }
});

//position validation in email address
const validatePostion = (email) => {
  const position = email.split("@")[0];
  // console.log(position);
  const allowedUsernames = ["ao", "dean", "ada", "dsw"]; // List of valid usernames

  if (allowedUsernames.includes(position)) {
    console.log(`Valid position: ${position}`);
    return true;
  } else {
    console.log(`Invalid position: ${position}`);
    return false;
  }
};

//faculty sign-up
app.post("/faculty/register", validateEmailDomain, async (req, res) => {
  try {
    const { email, password, userName } = req.body;
    const position = email.split("@")[0];
    const isValidPostion = validatePostion(email);
    if (!isValidPostion) return res.status(400).send("Invalid faculty email");
    const isFacultyExist = await Faculty.findOne({ email });
    if (isFacultyExist) {
      return res.status(400).send({
        isSuccess: false,
        message: "Faculty email already exists",
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
      position,
    });

    console.log(newFaculty);
    return res.status(201).send({
      isSuccess: true,
      message: "Faculty email registration successful",
    });
  } catch (error) {
    console.error("Error registering faculty:", error);
    return res.status(500).send({
      isSuccess: false,
      message: "Failed to register faculty",
    });
  }
});

//faculty sign-in
app.post("/faculty/login", async (req, res) => {
  const { email, password } = req.body;
  const dbEmail = await Faculty.findOne({ email });
  if (!dbEmail) {
    return res.status(400).send({
      isSuccess: false,
      message: "Invalid faculty email",
    });
  }
  const isPasswordEqual = await bcrypt.compare(password, dbEmail.password);
  if (isPasswordEqual) {
    const payload = { email };
    const jwtToken = jwt.sign(payload, "secret_token");
    return res.status(200).send({
      isSuccess: true,
      message: "Faculty login successful",
      jwt_token: jwtToken,
    });
  } else {
    return res.status(400).send({
      isSuccess: false,
      message: "Invalid password",
    });
  }
});

//faculty password change
app.put("/faculty/change-password", async (request, response) => {
  try {
    const { email, oldPassword, newPassword } = request.body;
    const dbFaculty = await Faculty.findOne({ email });

    if (!dbFaculty) {
      return response.status(400).send({
        isSuccess: false,
        message: "Invalid Faculty email",
      });
    }
    const isPasswordEqual = await bcrypt.compare(
      oldPassword,
      dbFaculty.password
    );
    if (!isPasswordEqual) {
      return response.status(400).send({
        isSuccess: false,
        message: "Invalid current password",
      });
    }
    if (newPassword.length < 8) {
      return response.status(400).send({
        isSuccess: false,
        message: "New password is too short",
      });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await Faculty.updateOne({ email }, { password: hashedPassword });
    return response.status(200).send({
      isSuccess: true,
      message: "Password updated",
    });
  } catch (error) {
    return response.status(500).send({
      isSuccess: false,
      message: "Failed to update password",
    });
  }
});

//student password change
app.put("/student/change-password", async (request, response) => {
  try {
    const { email, oldPassword, newPassword } = request.body;
    const dbStudent = await Student.findOne({ email });

    if (!dbStudent) {
      return response.status(400).send({
        isSuccess: false,
        message: "Invalid Student email",
      });
    }
    const isPasswordEqual = await bcrypt.compare(
      oldPassword,
      dbStudent.password
    );
    if (!isPasswordEqual) {
      return response.status(400).send({
        isSuccess: false,
        message: "Invalid current password",
      });
    }
    if (newPassword.length < 8) {
      return response.status(400).send({
        isSuccess: false,
        message: "New password is too short",
      });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await Student.updateOne({ email }, { password: hashedPassword });
    return response.status(200).send({
      isSuccess: true,
      message: "Password updated",
    });
  } catch (error) {
    return response.status(500).send({
      isSuccess: false,
      message: "Failed to update password",
    });
  }
});

app.get("/students", async (request, response) => {
  const Students = await Student.find({});
  response.send(Students);
});
