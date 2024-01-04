const express = require("express");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const secretKey = "Tgc@2023"; // Replace with your own secret key
const bcrypt = require("bcrypt");
const https = require("https");
const cors = require("cors");
const bodyParser = require("body-parser"); // Add bodyParser for parsing request bodies
const fs = require("fs");

const app = express();
const port = 8888;

const connection = mysql.createConnection({
  host: "15.207.42.176",
  user: "Tgc-Rajat-BataDB",
  password: "Lmasd&6#",
  database: "gamified_ad_cms",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Connect to MySQL
connection.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
    return;
  }
  console.log("Connected to MySQL");
});
app.use(cors());
app.use(express.json());

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.header("Authorization");

  if (!token) {
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token.replace("Bearer ", ""), secretKey);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("Error verifying token:", error);
    return res.status(401).json({ message: "Access denied. Invalid token." });
  }
};

// Signup route to generate JWT token
app.post("/signup", async (req, res) => {
  const {
    org_id,
    user_email,
    user_first_name,
    user_last_name,
    user_phone_number,
    user_organization_name,
    user_organization_password,
    user_status,
  } = req.body;

  // Check if required fields are present in the request body
  if (
    !user_email ||
    !user_first_name ||
    !user_last_name ||
    !user_phone_number ||
    !user_organization_name ||
    !user_organization_password ||
    !user_status
  ) {
    return res
      .status(400)
      .json({ message: "All fields are required for signup." });
  }

  try {
    // Check if the email already exists in the database
    const emailExists = await isEmailExists(user_email);
    if (emailExists) {
      return res.status(400).json({ message: "Email already exists." });
    }

    // Hash the user password before storing it in the database
    bcrypt.hash(user_organization_password, 10, (hashErr, hashedPassword) => {
      if (hashErr) {
        console.error("Error hashing password:", hashErr);
        return res.status(500).json({ message: "Internal Server Error" });
      }

      const upload_datetime = new Date(); // Get the current date and time

      // Insert user details into the tbl_user_details table
      const sql = `INSERT INTO tbl_user_details (org_id, user_email, user_first_name, user_last_name, user_phone_number, user_organization_name, user_organization_password, user_status, upload_datetime) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

      connection.query(
        sql,
        [
          org_id,
          user_email,
          user_first_name,
          user_last_name,
          user_phone_number,
          user_organization_name,
          hashedPassword, // Store hashed password in the database
          user_status,
          upload_datetime,
        ],
        (err, results) => {
          if (err) {
            console.error("Error inserting user details:", err);
            return res.status(500).json({ message: "Internal Server Error" });
          }

          // Generate a new token for the signed-up user
          const user = { user_email, user_id: results.insertId }; // Assuming there's an auto-incremented ID in tbl_user_details
          // const token = jwt.sign(user, secretKey, { expiresIn: "300s" }); // Token expires in 5 minutes for example
          res.json({ message: "User signed up successfully." });
        }
      );
    });
  } catch (error) {
    console.error("Error checking email existence:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Function to check if the email already exists in the database
const isEmailExists = (email) => {
  return new Promise((resolve, reject) => {
    const checkEmailQuery =
      "SELECT COUNT(*) AS count FROM tbl_user_details WHERE user_email = ?";
    connection.query(checkEmailQuery, [email], (err, results) => {
      if (err) {
        reject(err);
      } else {
        resolve(results[0].count > 0);
      }
    });
  });
};

// Login route to generate JWT token
app.post("/login", (req, res) => {
  const { user_email, user_organization_password } = req.body;

  // Check if username and password are present in the request body
  if (!user_email || !user_organization_password) {
    return res
      .status(400)
      .json({ message: "Username and password are required." });
  }

  // Retrieve hashed password from tbl_user_details
  const sql = `SELECT * FROM tbl_user_details WHERE user_email = ?`;

  connection.query(sql, [user_email], (err, results) => {
    if (err) {
      console.error("Error checking user credentials:", err);
      return res.status(500).json({ message: "Internal Server Error" });
    }

    if (results.length > 0) {
      // Compare hashed password with provided password
      const hashedPassword = results[0].user_organization_password;

      bcrypt.compare(
        user_organization_password,
        hashedPassword,
        (compareErr, match) => {
          if (compareErr) {
            console.error("Error comparing passwords:", compareErr);
            return res.status(500).json({ message: "Internal Server Error" });
          }

          if (match) {
            // Passwords match, generate a JWT token
            const user = { user_email, user_id: results[0].id_user };
            const token = jwt.sign(user, secretKey, { expiresIn: "300s" }); // Token expires in 5 minutes for example
            res.json({ message: "Login successful.", token });
          } else {
            // Invalid credentials
            res.status(401).json({ message: "Invalid credentials" });
          }
        }
      );
    } else {
      // User not found
      res.status(401).json({ message: "Invalid credentials" });
    }
  });
});

// Protected route
app.get("/protected", verifyToken, (req, res) => {
  // Access the authenticated user's information from req.user
  res.json({ message: "This is a protected resource.", user: req.user });
});

app.post("/verify", verifyToken, (req, res) => {
  try {
    res.json({ message: "Verified Successfully" });
  } catch (error) {
    console.error("Error in verify route:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// app.listen(port, () => {
//   console.log(`Server is running at http://localhost:${port}`);
// });

const httpsOptions = {
  key: fs.readFileSync("/opt/bitnami/apache/conf/connectopia.app.key"),
  cert: fs.readFileSync("/opt/bitnami/apache/conf/connectopia.app.crt"),
  // passphrase: "Tgc@0987",
};

const server = https.createServer(httpsOptions, app).listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
