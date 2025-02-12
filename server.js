import dotenv from "dotenv";
dotenv.config();
import express from "express";
import bodyParser from "body-parser";
import mysql from "mysql2";
import cors from "cors";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import multer from "multer";
import crypto from "crypto";
import Razorpay from "razorpay";
import path from "path";

const salt = 10;
const app = express();
const PORT = 8000;

app.use(express.json());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: [
      "http://localhost:3001",
      "http://localhost:3000",
      "https://radheenterprise.netlify.app",
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);
app.use(cookieParser());

// Create a connection pool
const pool = mysql.createPool({
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.DATABASE,
  port: process.env.PORT,
  waitForConnections: true,
  queueLimit: 0,
});

// Connect to the database
pool.getConnection((err, connection) => {
  if (err) {
    if (err.code === "ETIMEDOUT") {
      console.error(
        "Database connection timed out. Check your network or server status."
      );
    } else if (err.code === "ECONNREFUSED") {
      console.error(
        "Database connection was refused. Check your credentials or database status."
      );
    } else {
      console.error("Database connection failed:", err.message);
    }
  } else {
    console.log("Connected to the MySQL database.");
    connection.release(); // Release the connection back to the pool
  }
});

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Specify the directory to save uploaded files
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Append timestamp to the file name
  },
});

const upload = multer({ storage: storage });

// Route to handle sending inquiries
app.post("/send-inquiry", async (req, res) => {
  const { email, inquiry } = req.body;

  const mailOptions = {
    from: email,
    to: "mithilsuthar2603@gmail.com", // The email address you want to send to
    subject: "New Inquiry",
    text: `Inquiry from ${email}:\n\n${inquiry}`,
  };

  try {
    await transporter.sendMail(mailOptions); // Send the email using the transporter
    res.status(200).json({ message: "Inquiry sent successfully!" });
  } catch (error) {
    console.error("Error sending email:", error); // Log the actual error
    res.status(500).json({ error: "Error sending inquiry." });
  }
});

const verifyAdmin = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ Error: "You are not authenticated" });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decode) => {
    if (err) {
      return res.status(403).json({ Error: "Token is not correct" });
    }
    if (decode.user_type !== "Owner") {
      return res
        .status(403)
        .json({ Error: "You do not have admin privileges" });
    }
    req.name = decode.name;
    req.user_id = decode.user_id;
    req.user_type = decode.user_type;
    next();
  });
};

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ Error: "You are not authenticated" });
  } else {
    jwt.verify(token, process.env.JWT_SECRET, (err, decode) => {
      if (err) {
        return res.status(403).json({ Error: "Token is not correct" });
      } else {
        req.name = decode.name;
        req.user_id = decode.user_id;
        next();
      }
    });
  }
};

app.get("/auth/status", verifyUser, (req, res) => {
  res.status(200).json({ status: "Authenticated", name: req.name });
});

app.get("/", verifyUser, (req, res) => {
  return res.json({ status: "Success", name: req.name });
});

app.post("/register", (req, res) => {
  const requiredFields = [
    "first_name",
    "last_name",
    "email",
    "phone_number",
    "user_password",
  ];
  for (const field of requiredFields) {
    if (!req.body[field]) {
      return res
        .status(400)
        .json({ Error: `${field.replace("_", " ")} is required.` });
    }
  }

  const phoneNumberRegex = /^\+[1-9]\d{1,14}$/;
  const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
  const passwordRegex =
    /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/;

  if (!phoneNumberRegex.test(req.body.phone_number)) {
    return res.json({
      Error: "Invalid phone number format. Please include country code.",
    });
  }

  if (!emailRegex.test(req.body.email)) {
    return res.json({ Error: "Invalid email format!" });
  }

  if (!passwordRegex.test(req.body.user_password)) {
    return res.json({
      Error:
        "Password must be at least 6 characters long, contain a number and a special character.",
    });
  }

  // Check if the email already exists in the user_tbl
  const checkEmailSql = "SELECT email FROM user_tbl WHERE email = ?";
  pool.query(checkEmailSql, [req.body.email], (err, results) => {
    if (err) {
      console.error("SQL Error during email check:", err);
      return res
        .status(500)
        .json({ Error: "Database error during email check" });
    }

    if (results.length > 0) {
      return res.status(409).json({ message: "Email already exists." });
    }

    // Proceed with hashing the password and inserting into temp_user_tbl
    bcrypt.hash(req.body.user_password.toString(), salt, (err, hash) => {
      if (err) {
        console.error("Hashing Error:", err);
        return res.json({ Error: "Error while hashing password!" });
      }

      // Insert into temporary user table
      const sql =
        "INSERT INTO temp_user_tbl(first_name, last_name, email, phone_number, company_name, company_address, address_city, address_state, address_country, pincode, GST_no, user_password, otp, otp_expiration) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
      const values = [
        req.body.first_name,
        req.body.last_name,
        req.body.email,
        req.body.phone_number,
        req.body.company_name,
        req.body.company_address,
        req.body.address_city,
        req.body.address_state,
        req.body.address_country,
        req.body.pincode,
        req.body.GST_no,
        hash,
        null, // OTP will be generated and stored later
        null, // OTP expiration will be set later
      ];

      pool.query(sql, values, (err, result) => {
        if (err) {
          console.error("SQL Error during insert into temp_user_tbl:", err);
          return res.json({ Error: "Error inserting data in server" });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
        const otpExpiration = new Date(Date.now() + 10 * 60 * 1000); // OTP valid for 10 minutes

        // Update the temporary user with OTP and expiration
        const updateSql =
          "UPDATE temp_user_tbl SET otp = ?, otp_expiration = ? WHERE email = ?";
        const updateValues = [otp, otpExpiration, req.body.email];

        pool.query(updateSql, updateValues, (err) => {
          if (err) {
            console.error("SQL Error during OTP update:", err);
            return res.json({ Error: "Error updating OTP in server" });
          }

          // Send OTP email
          const mailOptions = {
            from: process.env.EMAIL_USER,
            to: req.body.email,
            subject: "Your OTP Code",
            html: `
              <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4; border-radius: 5px;">
                <h2 style="color: #333;">Welcome to Radhe Enterprise Pvt. Ltd.!</h2>
                <p style="color: #555;">Thank you for registering. Please use the following One-Time Password (OTP) to complete your registration:</p>
                <h1 style="font-size: 36px; color: #4CAF50; text-align: center; padding: 10px; border: 2px solid #4CAF50; border-radius: 5px; display: inline-block;">
                  ${otp}
                </h1>
                <p style="color: #555;">This OTP is valid for <strong>10 minutes</strong>.</p>
                <p style="color: #555;">If you did not request this, please ignore this email.</p>
                <footer style="margin-top: 20px; font-size: 12px; color: #777;">
                  <p>Thank you for choosing us!</p>
                  <p>Best Regards,<br>Radhe Enterprise Pvt. Ltd.</p>
                </footer>
              </div>
            `,
          };

          transporter.sendMail(mailOptions, (err) => {
            if (err) {
              console.error("Email Sending Error:", err);
              return res.json({ Error: "Error sending OTP email" });
            }

            return res.json({
              status: "Success",
              message:
                "User  registered successfully. Please check your email for the OTP.",
            });
          });
        });
      });
    });
  });
});

// OTP verification endpoint
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ Error: "Email and OTP are required." });
  }

  const sql =
    "SELECT otp, otp_expiration, user_password FROM temp_user_tbl WHERE email = ?";
  pool.query(sql, [email], (err, results) => {
    if (err) {
      if (err.code === "ER_DUP_ENTRY") {
        return res
          .status(409)
          .json({ status: "Error", message: "Email already Exists" });
      }
      console.error("SQL Error:", err);
      return res
        .status(500)
        .json({ Error: "Database error during OTP verification" });
    }

    if (results.length === 0) {
      return res.status(404).json({ Error: "User  not found." });
    }

    const { otp: storedOtp, otp_expiration, user_password } = results[0];

    // Check if OTP is valid and not expired
    if (storedOtp === otp && new Date() < new Date(otp_expiration)) {
      // Move user data from temp_user_tbl to user_tbl
      const insertSql =
        "INSERT INTO user_tbl(first_name, last_name, email, phone_number, company_name, company_address, address_city, address_state, address_country, pincode, GST_no, user_password, user_type, email_verified) SELECT first_name, last_name, email, phone_number, company_name, company_address, address_city, address_state, address_country, pincode, GST_no, ?, 'customer', true FROM temp_user_tbl WHERE email = ?";
      const insertValues = [user_password, email];

      pool.query(insertSql, insertValues, (err) => {
        if (err) {
          console.error("SQL Error:", err);
          return res
            .status(500)
            .json({ Error: "Error inserting data into user_tbl" });
        }

        // Delete the user from temp_user_tbl
        const deleteSql = "DELETE FROM temp_user_tbl WHERE email = ?";
        pool.query(deleteSql, [email], (err) => {
          if (err) {
            console.error("SQL Error:", err);
            return res
              .status(500)
              .json({ Error: "Error deleting temporary user" });
          }

          return res.json({
            status: "Success",
            message:
              "OTP verified successfully. Your registration is complete.",
          });
        });
      });
    } else {
      return res.status(400).json({ Error: "Invalid or expired OTP." });
    }
  });
});

// app.get("/verify-email", (req, res) => {
//   const { token } = req.query;

//   if (!token) {
//     return res.status(400).json({ Error: "Verification token is required" });
//   }

//   try {
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     const sql = "UPDATE user_tbl SET email_verified = ? WHERE email = ?";
//     const values = [true, decoded.email];

//     pool.query(sql, values, (err, result) => {
//       if (err) {
//         console.error("SQL Error:", err);
//         return res
//           .status(500)
//           .json({ Error: "Database error during verification" });
//       }

//       if (result.affectedRows === 0) {
//         return res
//           .status(404)
//           .json({ Error: "User not found or already verified" });
//       }

//       return res.json({
//         status: "Success",
//         message: "Email verified successfully",
//       });
//     });
//   } catch (err) {
//     console.error("JWT Error:", err);
//     return res.status(400).json({ Error: "Invalid or expired token" });
//   }
// });

app.post("/login", (req, res) => {
  const sql = "SELECT * FROM user_tbl WHERE email = ?";
  pool.query(sql, [req.body.email], (err, data) => {
    if (err) {
      return res.json({ Error: "Error Login in server!" });
    }
    if (data.length > 0) {
      bcrypt.compare(
        req.body.user_password.toString(),
        data[0].user_password,
        (err, response) => {
          if (err) {
            return res.json({ Error: "Password compare error" });
          }
          if (response) {
            const name = data[0].first_name;
            const user_id = data[0].user_id;
            const user_type = data[0].user_type;
            const token = jwt.sign(
              { name, user_id, user_type },
              process.env.JWT_SECRET,
              {
                expiresIn: "7d",
              }
            );
            res.cookie("token", token);
            return res.json({ status: "Success", user_type });
          } else {
            return res.json({ message: "Invalid Email or Password!" });
          }
        }
      );
    } else {
      return res.json({ message: "Email not found, Please Register!" });
    }
  });
});

app.get("/profile", verifyUser, (req, res) => {
  const sql = "SELECT * FROM user_tbl WHERE user_id = ?";

  pool.query(sql, [req.user_id], (err, data) => {
    if (err) {
      console.error("SQL Error:", err);
      return res.json({ Error: "Error fetching user profile data" });
    }

    if (data.length > 0) {
      // Exclude sensitive data like password from the response
      const userProfile = {
        first_name: data[0].first_name,
        last_name: data[0].last_name,
        email: data[0].email,
        phone_number: data[0].phone_number,
        company_name: data[0].company_name,
        company_address: data[0].company_address,
        address_city: data[0].address_city,
        address_state: data[0].address_state,
        address_country: data[0].address_country,
        pincode: data[0].pincode,
        GST_no: data[0].GST_no,
      };
      return res.json({ status: "Success", data: userProfile });
    } else {
      return res.json({ Error: "User not found!" });
    }
  });
});

// forget password method
app.post("/forgot-password", (req, res) => {
  const { email } = req.body;

  // Check if user exists
  const sql = "SELECT user_id FROM user_tbl WHERE email = ?";
  pool.query(sql, [email], (err, results) => {
    if (err) return res.status(500).json({ Error: "Database error!" });
    if (results.length === 0) {
      return res.status(404).json({ Error: "User not found!" });
    }

    // Generate token
    const resetToken = crypto.randomBytes(32).toString("hex");
    const expiryTime = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Store token in database
    const updateSql =
      "UPDATE user_tbl SET reset_token = ?, reset_token_expiry = ? WHERE email = ?";
    pool.query(updateSql, [resetToken, expiryTime, email], (err, result) => {
      if (err) return res.status(500).json({ Error: "Database update error!" });

      // Send email with reset link
      const resetLink = `http://${process.env.HOST_IP}/reset-password/${resetToken}`;
      sendEmail(
        email,
        "Password Reset Request",
        `Click here to reset your password: ${resetLink}`
      );

      res.json({ status: "Success", message: "Password reset email sent!" });
    });
  });
});

app.post("/reset-password", (req, res) => {
  const { email, user_password } = req.body;

  // Check if the user exists
  const sql = "SELECT * FROM user_tbl WHERE email = ?";
  pool.query(sql, [email], (err, data) => {
    if (err) {
      return res.json({ Error: "Error accessing the server!" });
    }
    if (data.length > 0) {
      // Hash the new password
      bcrypt.hash(user_password, 10, (err, hash) => {
        if (err) {
          return res.json({ Error: "Error hashing password!" });
        }

        // Update the user's password
        const updateSql =
          "UPDATE user_tbl SET user_password = ? WHERE email = ?";
        pool.query(updateSql, [hash, email], (err, result) => {
          if (err) {
            return res.json({ Error: "Error updating password!" });
          }
          return res.json({
            status: "Success",
            message: "Password reset successfully!",
          });
        });
      });
    } else {
      return res.json({ message: "Email not found!" });
    }
  });
});

app.put("/updateProfile", verifyUser, (req, res) => {
  const {
    first_name,
    last_name,
    phone_number,
    company_name,
    company_address,
    address_city,
    address_state,
    address_country,
    pincode,
    GST_no,
  } = req.body;

  const sql = `
    UPDATE user_tbl 
    SET 
      first_name = ?, 
      last_name = ?, 
      phone_number = ?, 
      company_name = ?, 
      company_address = ?, 
      address_city = ?, 
      address_state = ?, 
      address_country = ?, 
      pincode = ?, 
      GST_no = ?
    WHERE 
      first_name = ?
  `;

  pool.query(
    sql,
    [
      first_name,
      last_name,
      phone_number,
      company_name,
      company_address,
      address_city,
      address_state,
      address_country,
      pincode,
      GST_no,
      req.name,
    ],
    (err, result) => {
      if (err) {
        console.error("SQL Error:", err);
        return res.json({ Error: "Error updating user profile data" });
      }
      return res.json({
        status: "Success",
        message: "Profile updated successfully!",
      });
    }
  );
});

app.get("/logout", verifyUser, (req, res) => {
  res.clearCookie("token");
  return res.status(200).json({ status: "Success" });
});

// Retrieve all categories (Public Access)
app.get("/categories", (req, res) => {
  const sql = "SELECT * FROM category_tbl";
  pool.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(200).json(results);
  });
});

// Route to fetch products by category ID
app.get("/products/category/:categoryId", (req, res) => {
  const { categoryId } = req.params;

  const sql =
    "SELECT * FROM product_tbl WHERE category_id = ? AND deleted = 0 ";
  pool.query(sql, [categoryId], (err, results) => {
    if (err) {
      console.error("Error fetching products by category:", err);
      return res
        .status(500)
        .json({ message: "Server error", error: err.message });
    }

    if (results.length === 0) {
      return res
        .status(404)
        .json({ message: "No products found for this category" });
    }

    res.status(200).json(results);
  });
});

// Add a new category (Admin Access Only)
app.post("/categories", verifyUser, verifyAdmin, async (req, res) => {
  // You can add additional admin verification logic here
  const { category_name, category_description, category_img } = req.body;
  const sql =
    "INSERT INTO category_tbl (category_name, category_description, category_img) VALUES (?, ?, ?)";
  pool.query(
    sql,
    [category_name, category_description, JSON.stringify(category_img)],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({
        message: "Category added successfully",
        categoryId: result.insertId,
      });
    }
  );
});

// Retrieve all products (Public Access)
app.get("/products/all", (req, res) => {
  const sql = "SELECT * FROM product_tbl WHERE deleted = 0";
  pool.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(200).json(results);
  });
});

// Retrieve a specific product by productId (Public Access)
app.get("/products/:productId", (req, res) => {
  const { productId } = req.params;
  const sql = "SELECT * FROM product_tbl WHERE product_id = ?";
  pool.query(sql, [productId], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (result.length === 0)
      return res.status(404).json({ error: "Product not found" });
    res.status(200).json(result[0]);
  });
});

// Add a new product (Admin Access Only)
app.post("/products", verifyUser, verifyUser, verifyAdmin, async (req, res) => {
  const { category_id, product_name, product_description, product_img } =
    req.body;
  const sql =
    "INSERT INTO product_tbl (category_id, product_name, product_description, product_img) VALUES (?, ?, ?, ?)";
  pool.query(
    sql,
    [
      category_id,
      product_name,
      JSON.stringify(product_description),
      JSON.stringify(product_img),
    ],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({
        message: "Product added successfully",
        productId: result.insertId,
      });
    }
  );
});

// Add feedback for a product (Authenticated Users Only)
app.post("/products/:productId/feedback", verifyUser, (req, res) => {
  const { productId } = req.params;
  const { comment, rating } = req.body;
  if (!comment || !rating || rating < 1 || rating > 5)
    return res.status(400).json({ error: "Invalid feedback or rating" });
  const sql =
    "INSERT INTO feedback_tbl (product_id, comment, rating, user_id) VALUES (?, ?, ?, ?)";
  pool.query(sql, [productId, comment, rating, req.user_id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({
      message: "Feedback submitted successfully",
      feedbackId: result.insertId,
    });
  });
});

// Get all feedback for a product
app.get("/products/:productId/feedback", (req, res) => {
  const { productId } = req.params;
  const sql = `
    SELECT 
      f.feedback_id, 
      f.comment, 
      f.rating, 
      f.created_at, 
      u.first_name 
    FROM feedback_tbl f
    JOIN user_tbl u ON f.user_id = u.user_id
    WHERE f.product_id = ? 
    ORDER BY f.created_at DESC;
  `;
  pool.query(sql, [productId], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(200).json(results);
  });
});

// Utility function to wrap `mysql2` callbacks in Promises
const query = (sql, params) =>
  new Promise((resolve, reject) => {
    pool.query(sql, params, (error, results) => {
      if (error) return reject(error);
      resolve(results);
    });
  });

const beginTransaction = () =>
  new Promise((resolve, reject) => {
    pool.getConnection((err, connection) => {
      if (err) return reject(err);
      connection.beginTransaction((error) => {
        if (error) return reject(error);
        resolve(connection);
      });
    });
  });

const commitTransaction = (connection) =>
  new Promise((resolve, reject) => {
    connection.commit((error) => {
      if (error) return reject(error);
      connection.release();
      resolve();
    });
  });

const rollbackTransaction = (connection) =>
  new Promise((resolve, reject) => {
    connection.rollback(() => {
      connection.release();
      resolve();
    });
  });

app.post("/place-order", verifyUser, async (req, res) => {
  const {
    product_id,
    quantity,
    no_of_ends,
    creel_type,
    creel_pitch,
    bobin_length,
  } = req.body;

  // Convert fields to numbers
  const quantityNum = Number(quantity);
  const noOfEndsNum = Number(no_of_ends);
  const creelPitchNum = Number(creel_pitch);
  const bobinLengthNum = Number(bobin_length);

  // Validation
  if (
    !product_id ||
    !quantity ||
    !no_of_ends ||
    !creel_type ||
    !creel_pitch ||
    !bobin_length
  ) {
    return res.status(400).json({ error: "All fields are required." });
  }

  if (isNaN(quantityNum) || quantityNum <= 0) {
    return res
      .status(400)
      .json({ error: "Quantity must be a positive number." });
  }

  if (isNaN(noOfEndsNum) || noOfEndsNum <= 0) {
    return res
      .status(400)
      .json({ error: "No of Ends must be a positive number." });
  }

  if (isNaN(creelPitchNum) || creelPitchNum <= 0) {
    return res
      .status(400)
      .json({ error: "Creel Pitch must be a positive number." });
  }

  if (isNaN(bobinLengthNum) || bobinLengthNum <= 0) {
    return res
      .status(400)
      .json({ error: "Bobin Length must be a positive number." });
  }

  if (!["O", "U"].includes(creel_type)) {
    return res
      .status(400)
      .json({ error: "Invalid Creel Type. Allowed values are 'O' and 'U'." });
  }

  // Proceed with database operations
  try {
    const connection = await beginTransaction();

    const orderResult = await query(
      "INSERT INTO order_tbl (user_id, order_status) VALUES (?, ?)",
      [req.user_id, "Pending"]
    );
    const orderId = orderResult.insertId;

    await query(
      `INSERT INTO order_details_tbl 
         (order_id, product_id, quantity, no_of_ends, creel_type, creel_pitch, bobin_length)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        orderId,
        product_id,
        quantityNum,
        noOfEndsNum,
        creel_type,
        creelPitchNum,
        bobinLengthNum,
      ]
    );

    await commitTransaction(connection);

    const ownerNumber = "917041177240";
    const message = encodeURIComponent(`New Order Placed!
          Order ID: ${orderId}
          Product ID: ${product_id}
          Quantity: ${quantityNum}
          Specifications:
          - No. of Ends: ${noOfEndsNum}
          - Creel Type: ${creel_type}
          - Creel Pitch: ${creelPitchNum}
          - Bobin Length: ${bobinLengthNum}`);
    const whatsappURL = `https://wa.me/${ownerNumber}?text=${message}`;

    res.status(200).json({ orderId, whatsappURL });
  } catch (err) {
    if (connection) await rollbackTransaction(connection);
    console.error("Error placing order:", err);
    res.status(500).json({ error: "Failed to place order" });
  }
});

app.get("/orders", verifyUser, async (req, res) => {
  try {
    // Fetch orders along with product, order, payment, delivery, and service details
    const orders = await query(
      `
      SELECT 
      o.order_id, o.order_status, o.order_date, 
      od.product_id, p.product_name, 
      od.quantity, od.no_of_ends, od.creel_type, od.creel_pitch, od.bobin_length, 
      pm.payment_amount, pm.payment_status, pm.installment_number, pm.payment_type, pm.payment_method, 
      d.delivery_status, s.service_status,
      u.first_name AS user_first_name, u.email AS user_email, u.phone_number AS user_phone_number
      FROM order_tbl o
      JOIN order_details_tbl od ON o.order_id = od.order_id
      JOIN product_tbl p ON od.product_id = p.product_id
      LEFT JOIN payment_tbl pm ON o.order_id = pm.order_id
      LEFT JOIN delivery_tbl d ON o.order_id = d.order_id
      LEFT JOIN service_tbl s ON o.order_id = s.order_id
      JOIN user_tbl u ON o.user_id = u.user_id
      WHERE o.user_id = ?
      `,
      [req.user_id]
    );

    // If no orders are found, return an empty array
    if (!orders.length) {
      return res.status(200).json({ orders: [] });
    }

    // Return the fetched orders as JSON
    res.status(200).json({ orders });
  } catch (err) {
    console.error("Error fetching orders:", err);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});

app.get("/admin/total-users", async (req, res) => {
  try {
    const result = await query("SELECT COUNT(*) AS total_users FROM user_tbl");
    res.status(200).json(result[0]);
  } catch (error) {
    console.error("Error fetching total users:", error);
    res.status(500).json({ error: "Failed to fetch total users" });
  }
});

app.get("/admin/pending-orders", async (req, res) => {
  try {
    const result = await query(
      "SELECT COUNT(*) AS pending_orders FROM order_tbl WHERE order_status = 'Pending'"
    );
    res.status(200).json(result[0]);
  } catch (error) {
    console.error("Error fetching pending orders:", error);
    res.status(500).json({ error: "Failed to fetch pending orders" });
  }
});

app.get("/admin/pending-services", async (req, res) => {
  try {
    const result = await query(`
      SELECT 
        s.service_id, 
        s.order_id, 
        s.user_id, 
        s.payment_id, 
        s.requested_date, 
        s.service_type, 
        s.service_notes, 
        s.service_cost, 
        s.service_status,
        p.payment_status  -- Fetching payment_status from payment_tbl
      FROM service_tbl s
      LEFT JOIN payment_tbl p ON s.payment_id = p.payment_id
      WHERE s.service_status = 'Pending'
    `);

    res.status(200).json(result);
  } catch (error) {
    console.error("Error fetching pending services:", error);
    res.status(500).json({ error: "Failed to fetch pending services" });
  }
});

app.get("/admin/revenue", async (req, res) => {
  try {
    const result = await query(
      "SELECT SUM(payment_amount) AS total_revenue FROM payment_tbl WHERE payment_status = 'Completed'"
    );
    res.status(200).json(result[0]);
  } catch (error) {
    console.error("Error fetching revenue:", error);
    res.status(500).json({ error: "Failed to fetch revenue" });
  }
});

app.get("/admin/feedback-count", async (req, res) => {
  try {
    const result = await query(
      "SELECT COUNT(*) AS feedback_count FROM feedback_tbl"
    );
    res.status(200).json(result[0]);
  } catch (error) {
    console.error("Error fetching feedback count:", error);
    res.status(500).json({ error: "Failed to fetch feedback count" });
  }
});

app.get("/admin/recent-orders", async (req, res) => {
  try {
    const result = await query(
      `
      SELECT o.order_id, o.order_status, o.order_date, od.product_id, p.product_name, 
             od.quantity, od.no_of_ends, od.creel_type, od.creel_pitch, od.bobin_length 
      FROM order_tbl o 
      JOIN order_details_tbl od ON o.order_id = od.order_id 
      JOIN product_tbl p ON od.product_id = p.product_id 
      WHERE o.order_status = 'Pending' 
      ORDER BY o.order_date DESC 
      LIMIT 5
      `
    );

    res.status(200).json(result);
  } catch (error) {
    console.error("Error fetching pending orders:", error);
    res.status(500).json({ error: "Failed to fetch pending orders" });
  }
});

// Fetch all users
app.get("/users", verifyUser, verifyAdmin, async (req, res) => {
  try {
    pool.query(
      "SELECT user_id, first_name, last_name, email, user_type FROM user_tbl",
      (error, results) => {
        if (error) {
          throw error;
        }
        res.status(200).json(results);
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch users." });
  }
});

// Delete a user
app.delete("/users/:id", verifyUser, verifyAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    pool.query(
      "DELETE FROM user_tbl WHERE user_id = ?",
      [id],
      (error, results) => {
        if (error) {
          if (error.code === "ER_ROW_IS_REFERENCED_2") {
            return res.status(400).json({
              message:
                "Cannot delete user. The user has related orders in the system.",
            });
          }
          return res
            .status(500)
            .json({ message: "An unexpected error occurred.", error });
        }
        res.status(200).json({ message: "User deleted successfully." });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to delete user." });
  }
});

// Fetch all categories
app.get("/categories", verifyUser, verifyAdmin, async (req, res) => {
  try {
    pool.query(
      `SELECT 
         category_id, 
         user_id AS owner_id, 
         category_name, 
         category_description, 
         category_img, 
         created_at, 
         update_at 
       FROM category_tbl`,
      (error, results) => {
        if (error) {
          throw error;
        }
        res.status(200).json(results);
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch categories." });
  }
});

// Create a new category
app.post("/categories", verifyUser, verifyAdmin, async (req, res) => {
  const { category_name, category_description, category_img } = req.body;

  try {
    await pool.query(
      "INSERT INTO category_tbl (category_name, category_description, category_img, created_at, update_at, user_id) VALUES (?, ?, ?, NOW(), NOW(), ?)",
      [
        category_name,
        category_description,
        JSON.stringify(category_img),
        req.user.id,
      ]
    );
    res.status(201).json({ message: "Category created successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to create category." });
  }
});

// Update a category
app.put("/categories/:id", verifyUser, verifyAdmin, async (req, res) => {
  const { id } = req.params; // The ID of the category to be updated
  const { category_name, category_description, category_img } = req.body;
  const user_id = req.user_id; // Correctly access req.user_id

  try {
    pool.query(
      `UPDATE category_tbl 
       SET 
         user_id = ?, 
         category_name = ?, 
         category_description = ?, 
         category_img = ?
       WHERE category_id = ?`,
      [
        user_id,
        category_name,
        category_description,
        JSON.stringify(category_img),
        id,
      ],
      (error, results) => {
        if (error) {
          throw error;
        }
        res.status(200).json({ message: "Category updated successfully." });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to update category." });
  }
});

// Delete a category
app.delete("/categories/:id", verifyUser, verifyAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    // Check if there are any products in the category
    pool.query(
      "SELECT COUNT(*) AS productCount FROM product_tbl WHERE category_id = ?",
      [id],
      (error, results) => {
        if (error) {
          throw error;
        }

        const productCount = results[0].productCount;
        if (productCount > 0) {
          // Prevent deletion if products are present
          return res.status(400).json({
            message:
              "Cannot delete category with products. Remove associated products first.",
          });
        }

        // Proceed to delete the category
        pool.query(
          "DELETE FROM category_tbl WHERE category_id = ?",
          [id],
          (deleteError, deleteResults) => {
            if (deleteError) {
              throw deleteError;
            }
            res.status(200).json({ message: "Category deleted successfully." });
          }
        );
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to delete category." });
  }
});

// GET /products
app.get("/products", verifyUser, verifyAdmin, async (req, res) => {
  const { category_id, product_name, page = 1, limit = 10 } = req.query;
  const offset = (page - 1) * limit;

  try {
    let query = `
      SELECT 
        product_id, 
        category_id,
        user_id AS owner_id, 
        product_name, 
        product_description, 
        product_img,
        created_at, 
        update_at 
      FROM product_tbl
      WHERE deleted = 0 
    `;
    const params = [];

    // Add filters
    if (category_id) {
      query += " AND category_id = ?";
      params.push(category_id);
    }

    if (product_name) {
      query += " AND product_name LIKE ?";
      params.push(`%${product_name}%`);
    }

    query += ` LIMIT ? OFFSET ?`;
    params.push(Number(limit), Number(offset));

    pool.query(query, params, (error, results) => {
      if (error) {
        console.error("Database query error:", error);
        return res.status(500).json({ message: "Database query error." });
      }

      // No need to parse product_description and product_img
      const parsedResults = results.map((result) => ({
        ...result,
        product_description: result.product_description || [], // Use as is
        product_img: result.product_img || [], // Use as is
      }));

      res.status(200).json(parsedResults);
    });
  } catch (error) {
    console.error("Unexpected error:", error);
    res.status(500).json({ message: "Failed to fetch products." });
  }
});

// POST /products
app.post("/products", verifyUser, verifyAdmin, async (req, res) => {
  const { category_id, product_name, product_description, product_img } =
    req.body;

  try {
    // Parse the product description input (admin enters like: ["RTR, RTF", "Hi, Hello"])
    let parsedDescription = [];
    try {
      parsedDescription = JSON.parse(product_description); // Parsing the input JSON string
      if (!Array.isArray(parsedDescription)) {
        return res.status(400).json({
          message: "Invalid JSON array format for product description.",
        });
      }
    } catch (error) {
      return res
        .status(400)
        .json({ message: "Invalid JSON format for product description." });
    }

    const productDescriptionJson = JSON.stringify(parsedDescription); // Store as JSON string
    const productImgJson = JSON.stringify(product_img || []);

    pool.query(
      `INSERT INTO product_tbl 
         (category_id, user_id, product_name, product_description, product_img, created_at, update_at) 
       VALUES (?, ?, ?, ?, ?, NOW(), NOW())`,
      [
        category_id,
        req.user_id,
        product_name,
        productDescriptionJson,
        productImgJson,
      ],
      (error, results) => {
        if (error) {
          return res.status(500).json({ message: "Database error." });
        }
        res.status(201).json({ message: "Product created successfully." });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to create product." });
  }
});

// PUT /products/:id
app.put("/products/:id", verifyUser, verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const { category_id, product_name, product_description, product_img } =
    req.body;
  const user_id = req.user_id;

  try {
    // Ensure product_description is a valid JSON string
    let parsedDescription = [];
    if (typeof product_description === "string") {
      try {
        parsedDescription = JSON.parse(product_description); // Parsing the input JSON string
        if (!Array.isArray(parsedDescription)) {
          return res.status(400).json({
            message: "Invalid JSON array format for product description.",
          });
        }
      } catch (error) {
        return res
          .status(400)
          .json({ message: "Invalid JSON format for product description." });
      }
    } else if (Array.isArray(product_description)) {
      parsedDescription = product_description; // If it's already an array, use it directly
    } else {
      return res.status(400).json({
        message: "Product description must be an array or a valid JSON string.",
      });
    }

    const productDescriptionJson = JSON.stringify(parsedDescription); // Store as JSON string
    const productImgJson = JSON.stringify(product_img || []);

    pool.query(
      `UPDATE product_tbl 
       SET 
         category_id = ?, 
         user_id = ?, 
         product_name = ?, 
         product_description = ?, 
         product_img = ?
       WHERE product_id = ?`,
      [
        category_id,
        user_id,
        product_name,
        productDescriptionJson,
        productImgJson,
        id,
      ],
      (error, results) => {
        if (error) {
          return res.status(500).json({ message: "Database error." });
        }

        if (results.affectedRows === 0) {
          return res.status(404).json({ message: "Product not found." });
        }

        res.status(200).json({ message: "Product updated successfully." });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to update product." });
  }
});

app.delete("/products/:id", verifyUser, verifyAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    pool.query(
      "DELETE FROM product_tbl WHERE product_id = ?",
      [id],
      (error, results) => {
        if (error) {
          throw error;
        }
        res.status(200).json({ message: "Product deleted successfully." });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to delete product." });
  }
});

// Soft delete endpoint
app.put(
  "/products/:id/soft-delete",
  verifyUser,
  verifyAdmin,
  async (req, res) => {
    const { id } = req.params;
    try {
      // Check if there are any orders associated with this product
      pool.query(
        "SELECT COUNT(*) AS orderCount FROM order_details_tbl WHERE product_id = ?",
        [id],
        (error, results) => {
          if (error) {
            throw error;
          }

          const orderCount = results[0].orderCount;

          if (orderCount > 0) {
            return res.status(400).json({
              message:
                "Cannot delete product. There are orders associated with it.",
            });
          }

          // Proceed with soft delete
          pool.query(
            "UPDATE product_tbl SET deleted = 1 WHERE product_id = ?",
            [id],
            (error, results) => {
              if (error) {
                throw error;
              }
              console.log(`Product ${id} soft deleted successfully.`); // Log the soft delete
              res
                .status(200)
                .json({ message: "Product soft deleted successfully." });
            }
          );
        }
      );
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Failed to soft delete product." });
    }
  }
);

// Get all orders with details
app.get("/admin/orders", verifyUser, verifyAdmin, async (req, res) => {
  try {
    const ordersQuery = `
      SELECT 
        o.order_id, 
        o.user_id, 
        u.first_name, 
        u.email, 
        o.order_date, 
        o.order_status,
        od.order_details_id, 
        od.product_id, 
        p.product_name,
        od.quantity, 
        od.no_of_ends, 
        od.creel_type, 
        od.creel_pitch, 
        od.bobin_length
      FROM order_tbl o
      LEFT JOIN user_tbl u ON o.user_id = u.user_id
      LEFT JOIN order_details_tbl od ON o.order_id = od.order_id
      LEFT JOIN product_tbl p ON od.product_id = p.product_id
      ORDER BY o.order_date DESC
    `;

    pool.query(ordersQuery, (error, results) => {
      if (error) {
        throw error;
      }
      res.status(200).json(results);
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch orders." });
  }
});

// Update an order's status
app.put("/orders/:id", verifyUser, verifyAdmin, async (req, res) => {
  const { id } = req.params; // Order ID
  const { order_status } = req.body;

  if (
    !["Pending", "Confirmed", "Shipped", "Cancelled", "Delivered"].includes(
      order_status
    )
  ) {
    return res.status(400).json({ message: "Invalid order status." });
  }

  try {
    pool.query(
      "UPDATE order_tbl SET order_status = ? WHERE order_id = ?",
      [order_status, id],
      (error, results) => {
        if (error) {
          throw error;
        }
        res.status(200).json({ message: "Order status updated successfully." });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to update order status." });
  }
});

// Delete an order
app.delete("/orders/:id", verifyUser, verifyAdmin, (req, res) => {
  const { id } = req.params;

  // First, delete from order_details_tbl
  pool.query(
    "DELETE FROM order_details_tbl WHERE order_id = ?",
    [id],
    (error, results) => {
      if (error) {
        console.error("Error deleting from order_details_tbl:", error.message);
        return res
          .status(500)
          .json({ message: "Failed to delete order details." });
      }

      // Then, delete from order_tbl
      pool.query(
        "DELETE FROM order_tbl WHERE order_id = ?",
        [id],
        (error, results) => {
          if (error) {
            console.error("Error deleting from order_tbl:", error.message);
            return res.status(500).json({ message: "Failed to delete order." });
          }

          // Success
          res.status(200).json({ message: "Order deleted successfully." });
        }
      );
    }
  );
});

// GET all payments
app.get("/admin/payments", (req, res) => {
  const sql = `
    SELECT 
      razorpay_order_id,
      payment_id,
      order_id,
      payment_amount,
      payment_date,
      payment_method,
      bill,
      payment_status,
      total_amount,
      remaining_amount,
      installment_number,
      payment_type,
      created_at,
      update_at
    FROM payment_tbl
  `;
  pool.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching payments:", err);
      res.status(500).json({ message: "Failed to fetch payments" });
    } else {
      res.json(results);
    }
  });
});

app.post(
  "/admin/payments",
  verifyUser,
  verifyAdmin,
  upload.single("billFile"),
  async (req, res) => {
    console.log("Request body:", req.body); // Check if all fields are coming through correctly

    const {
      payment_amount,
      payment_method,
      payment_type,
      order_id,
      total_amount,
      installment_number,
    } = req.body; // Destructure payment details

    console.log("Parsed payment details:", {
      payment_amount,
      payment_method,
      payment_type,
      order_id,
      total_amount,
      installment_number,
    });

    try {
      // Validate required fields
      if (
        !payment_amount ||
        !payment_method ||
        !payment_type ||
        !order_id ||
        !installment_number
      ) {
        return res.status(400).json({ error: "Missing required fields." });
      }

      // Convert installment_number to string to match ENUM type
      const installmentNumber = String(installment_number);

      console.log("Installment number:", installmentNumber);

      const paymentAmount = parseFloat(payment_amount);
      const totalAmount = parseFloat(total_amount);

      // Insert payment details
      const sql = `
      INSERT INTO payment_tbl (
        payment_amount, payment_method, installment_number, payment_type, total_amount, order_id, bill
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

      // Save the file path to the database if a file was uploaded
      const billFilePath = req.file ? req.file.path : null;

      await pool.promise().query(sql, [
        paymentAmount,
        payment_method,
        installmentNumber, // Use the string value
        payment_type,
        totalAmount,
        order_id,
        billFilePath,
      ]);

      res.status(200).send("Payment created successfully.");
    } catch (err) {
      console.error("Error processing payment:", err);
      res.status(500).send("Failed to process payment.");
    }
  }
);

app.put(
  "/admin/payments/:paymentId",
  verifyUser,
  verifyAdmin,
  async (req, res) => {
    const { paymentId } = req.params;
    const { payment_status } = req.body;

    try {
      const sql = `
      UPDATE payment_tbl 
      SET payment_status = ? 
      WHERE payment_id = ?
    `;
      await pool.promise().query(sql, [payment_status, paymentId]);

      res.status(200).json({ message: "Payment status updated successfully." });
    } catch (error) {
      console.error("Error updating payment status:", error);
      res.status(500).json({ error: "Failed to update payment status." });
    }
  }
);

app.post("/create-order", (req, res) => {
  const razorpay = new Razorpay({
    key_id: process.env.KEY_ID,
    key_secret: process.env.KEY_SECRET,
  });

  const options = req.body;

  // Fetch the payment details from the database using order_id
  const sql =
    "SELECT * FROM payment_tbl WHERE order_id = ? AND installment_number = ?";
  pool.query(
    sql,
    [options.order_id, options.installment_number],
    (err, results) => {
      if (err) {
        console.error("Error fetching payment details:", err);
        return res.status(500).send("Error fetching payment details");
      }

      if (results.length === 0) {
        return res
          .status(404)
          .send("Payment details not found for this order and installment.");
      }

      const paymentDetails = results[0];

      // Ensure the amount is in the smallest unit (e.g., paise)
      const amount = Math.round(paymentDetails.payment_amount * 100); // Convert to paise

      const orderOptions = {
        amount, // Razorpay expects amount in the smallest unit
        currency: "INR",
        receipt: paymentDetails.order_id.toString(),
        payment_capture: 1, // auto-capture the payment
      };

      razorpay.orders.create(orderOptions, (err, order) => {
        if (err) {
          console.error("Error creating Razorpay order:", err);
          return res.status(500).send("Error creating Razorpay order");
        }

        // Update the payment_tbl with the Razorpay order ID
        const updateSql = `
        UPDATE payment_tbl 
        SET razorpay_order_id = ?, payment_status = 'Pending' 
        WHERE order_id = ? AND installment_number = ?
      `;
        pool.query(
          updateSql,
          [order.id, options.order_id, options.installment_number],
          (updateErr) => {
            if (updateErr) {
              console.error(
                "Error updating Razorpay order ID in database:",
                updateErr
              );
              return res
                .status(500)
                .send("Error saving Razorpay order ID to database");
            }

            // Send the response to the frontend
            res.json({
              key: process.env.KEY_ID,
              order: order,
            });
          }
        );
      });
    }
  );
});

app.post("/verify-payment", async (req, res) => {
  const { payment_id, order_id: razorpay_order_id, signature } = req.body;

  // Generate the expected signature
  const generatedSignature = crypto
    .createHmac("sha256", process.env.KEY_SECRET)
    .update(razorpay_order_id + "|" + payment_id)
    .digest("hex");

  // Compare the generated signature with the received signature
  if (generatedSignature === signature) {
    try {
      // Step 1: Fetch the installment number using razorpay_order_id
      const fetchSql =
        "SELECT order_id, installment_number FROM payment_tbl WHERE razorpay_order_id = ?";
      const [rows] = await pool.promise().query(fetchSql, [razorpay_order_id]);

      if (rows.length === 0) {
        console.error("No matching order found for Razorpay order ID");
        return res.status(400).json({ error: "Order not found" });
      }

      const dbOrderId = rows[0].order_id;
      const installmentNumber = rows[0].installment_number;

      // Step 2: Update the payment status and remaining amount in payment_tbl
      const updateSql = `
        UPDATE payment_tbl 
        SET payment_status = 'Completed', remaining_amount = 0 
        WHERE order_id = ? AND installment_number = ?
      `;
      await pool.promise().query(updateSql, [dbOrderId, installmentNumber]);

      res.status(200).json({ message: "Payment verified successfully" });
    } catch (err) {
      console.error("Error updating order status:", err);
      res.status(500).json({ error: "Error updating order status" });
    }
  } else {
    res.status(400).json({ error: "Invalid signature" });
  }
});

// Create Delivery
app.post("/admin/delivery", verifyUser, verifyAdmin, async (req, res) => {
  const { paymentId } = req.body;

  try {
    // Step 1: Fetch the order_id using paymentId
    const fetchSql = "SELECT order_id FROM payment_tbl WHERE payment_id = ?";
    const [rows] = await pool.promise().query(fetchSql, [paymentId]);

    if (rows.length === 0) {
      console.error("No matching payment found for payment ID");
      return res.status(400).json({ error: "Payment not found" });
    }

    const orderId = rows[0].order_id;

    // Step 2: Insert a new delivery record
    const deliveryDate = new Date();
    const status = "Pending"; // Default status for new deliveries

    const insertSql = `
      INSERT INTO delivery_tbl (order_id, delivery_date, delivery_status) 
      VALUES (?, ?, ?)
    `;
    const [result] = await pool
      .promise()
      .query(insertSql, [orderId, deliveryDate, status]);

    // Step 3: Return the created delivery details
    res.status(201).json({
      delivery_id: result.insertId,
      order_id: orderId,
      delivery_date: deliveryDate,
      status: status,
    });
  } catch (err) {
    console.error("Error creating delivery:", err);
    res.status(500).json({ error: "Error creating delivery" });
  }
});

// Get All Deliveries
app.get("/admin/deliveries", async (req, res) => {
  try {
    const fetchSql = `
      SELECT 
        d.delivery_id, 
        d.order_id, 
        d.delivery_status, 
        d.delivery_date, 
        p.payment_id, 
        p.payment_status 
      FROM 
        delivery_tbl d
      JOIN 
        payment_tbl p ON d.order_id = p.order_id
    `; // Adjust the query as necessary
    const [rows] = await pool.promise().query(fetchSql);

    res.status(200).json(rows);
  } catch (err) {
    console.error("Error fetching deliveries:", err);
    res.status(500).json({ error: "Error fetching deliveries" });
  }
});

// Update Delivery Status
app.put("/admin/delivery/:id", verifyUser, async (req, res) => {
  const { id } = req.params;
  const { delivery_status } = req.body;

  try {
    // Update the delivery status
    const updateSql = `
      UPDATE delivery_tbl 
      SET delivery_status = ? 
      WHERE delivery_id = ?
    `;
    await pool.promise().query(updateSql, [delivery_status, id]);

    // // Check if the delivery status is 'Delivered'
    // if (delivery_status === "Delivered") {
    //   // Fetch the order_id associated with this delivery
    //   const orderSql = `
    //     SELECT order_id
    //     FROM delivery_tbl
    //     WHERE delivery_id = ?
    //   `;
    //   const [orderRows] = await pool.promise().query(orderSql, [id]);

    //   if (orderRows.length > 0) {
    //     const orderId = orderRows[0].order_id;

    //     // Insert a new record into the service_tbl
    //     const serviceSql = `
    //       INSERT INTO service_tbl (order_id, user_id, service_type, service_notes, service_status)
    //       VALUES (?, ?, ?, ?, 'Pending')
    //     `;

    //     // Use the user_id from the request context
    //     const userId = req.user_id; // This is set by your verifyUser  middleware
    //     const serviceType = "Maintenance"; // Default service type, adjust as needed
    //     const serviceNotes = ""; // You can also pass notes if needed

    //     // Insert the service request into the service_tbl
    //     await pool
    //       .promise()
    //       .query(serviceSql, [orderId, userId, serviceType, serviceNotes]);
    //   }
    // }

    res.status(200).json({ message: "Delivery status updated successfully." });
  } catch (err) {
    console.error("Error updating delivery status:", err);
    res.status(500).json({ error: "Error updating delivery status" });
  }
});

app.post("/request-service", verifyUser, async (req, res) => {
  const { order_id, service_type, service_notes } = req.body;

  try {
    const sql = `
      INSERT INTO service_tbl (order_id, user_id, service_type, service_notes, requested_date)
      VALUES (?, ?, ?, ?, NOW())
    `;
    await pool
      .promise()
      .query(sql, [order_id, req.user_id, service_type, service_notes]);

    res
      .status(200)
      .json({ message: "Service request submitted successfully." });
  } catch (error) {
    console.error("Error processing service request:", error);
    res.status(500).json({ error: "Failed to submit service request." });
  }
});

app.put(
  "/admin/services/:serviceId",
  verifyUser,
  verifyAdmin,
  async (req, res) => {
    const { serviceId } = req.params;
    const { service_status } = req.body;

    try {
      const sql = `
      UPDATE service_tbl 
      SET service_status = ? 
      WHERE service_id = ?
    `;
      await pool.promise().query(sql, [service_status, serviceId]);

      res.status(200).json({ message: "Service status updated successfully." });
    } catch (error) {
      console.error("Error updating service status:", error);
      res.status(500).json({ error: "Failed to update service status." });
    }
  }
);

app.get("/admin/services", verifyUser, verifyAdmin, async (req, res) => {
  try {
    const sql = `
      SELECT 
        s.service_id, 
        s.order_id, 
        s.user_id, 
        s.payment_id, 
        s.requested_date, 
        s.service_type, 
        s.service_notes, 
        s.service_cost, 
        s.service_status,
        p.payment_status  -- Fetching payment_status from payment_tbl
      FROM service_tbl s
      LEFT JOIN payment_tbl p ON s.payment_id = p.payment_id  -- Joining with payment_tbl
    `;
    const [rows] = await pool.promise().query(sql);
    res.status(200).json(rows);
  } catch (error) {
    console.error("Error fetching services:", error);
    res.status(500).json({ error: "Failed to fetch services." });
  }
});

app.post(
  "/admin/service-payments",
  verifyUser,
  verifyAdmin,
  upload.single("billFile"), // If you want to allow bill uploads
  async (req, res) => {
    const { service_cost, payment_method, payment_type, order_id } = JSON.parse(
      req.body.paymentDetails
    ); // Parse the payment details from the request body

    try {
      // Validate required fields
      if (!service_cost || !payment_method || !payment_type || !order_id) {
        return res.status(400).json({ error: "Missing required fields." });
      }

      const paymentAmount = parseFloat(service_cost);

      // Insert the new payment record
      const paymentSql = `
      INSERT INTO payment_tbl (
        payment_amount, payment_method, payment_type, order_id, bill
      ) VALUES (?, ?, ?, ?, ?)
    `;

      // Save the file path to the database if a file was uploaded
      const billFilePath = req.file ? req.file.path : null;

      // Create the payment record
      const [paymentResult] = await pool.promise().query(paymentSql, [
        paymentAmount,
        payment_method,
        payment_type,
        order_id,
        billFilePath, // Save the file path to the database
      ]);

      // Update the service_tbl to link the payment
      const paymentId = paymentResult.insertId; // Get the ID of the newly created payment
      const updateServiceSql = `
        UPDATE service_tbl 
        SET payment_id = ?, service_cost = ? 
        WHERE order_id = ?
      `;

      await pool.promise().query(updateServiceSql, [
        paymentId,
        paymentAmount, // Update the service cost in the service_tbl
        order_id,
      ]);

      res.status(200).send("Service payment created successfully.");
    } catch (err) {
      console.error("Error processing service payment:", err);
      res.status(500).send("Failed to process service payment.");
    }
  }
);

// Routes for Reports
app.get("/admin/reports/users", async (req, res) => {
  try {
    const result = await query(`
      SELECT user_id, first_name, last_name, email, registration_date 
      FROM user_tbl 
      ORDER BY registration_date DESC 
      LIMIT 15
    `);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Failed to fetch users report" });
  }
});

app.get("/admin/reports/orders", async (req, res) => {
  try {
    const result = await query(`
      SELECT o.order_id, o.user_id, p.product_name, od.quantity, od.order_status, o.order_date 
      FROM order_tbl o JOIN product_tbl p ON od.product_id = p.product_id JOIN order_details_tbl od ON o.order_id = od.order_id ORDER BY order_date DESC 
      LIMIT 9
    `);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error fetching orders report:", error);
    res.status(500).json({ error: "Failed to fetch orders report" });
  }
});

app.get("/admin/reports/orders/pending", async (req, res) => {
  try {
    const result = await query(`
      SELECT o.order_id, o.order_status, o.order_date, od.product_id, p.product_name, 
             od.quantity, od.no_of_ends, od.creel_type, od.creel_pitch, od.bobin_length 
      FROM order_tbl o 
      JOIN order_details_tbl od ON o.order_id = od.order_id 
      JOIN product_tbl p ON od.product_id = p.product_id 
      WHERE o.order_status = 'Pending' 
      ORDER BY o.order_date DESC 
      LIMIT 9
    `);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error fetching pending orders:", error);
    res.status(500).json({ error: "Failed to fetch pending orders" });
  }
});

app.get("/admin/reports/orders/completed", async (req, res) => {
  try {
    const result = await query(`
      SELECT o.order_id, o.order_status, o.order_date, od.product_id, p.product_name, 
             od.quantity, od.no_of_ends, od.creel_type, od.creel_pitch, od.bobin_length 
      FROM order_tbl o 
      JOIN order_details_tbl od ON o.order_id = od.order_id 
      JOIN product_tbl p ON od.product_id = p.product_id 
      WHERE o.order_status = 'Delivered'
      ORDER BY order_date DESC 
      LIMIT 15
    `);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error fetching completed orders:", error);
    res.status(500).json({ error: "Failed to fetch completed orders" });
  }
});

app.get("/admin/reports/revenue", async (req, res) => {
  try {
    const result = await query(`
      SELECT DATE_FORMAT(payment_date, '%Y-%m') AS month, SUM(payment_amount) AS total_revenue 
      FROM payment_tbl 
      WHERE payment_status = 'Completed' 
      GROUP BY month 
      ORDER BY month DESC
    `);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error fetching revenue report:", error);
    res.status(500).json({ error: "Failed to fetch revenue report" });
  }
});

app.get("/admin/reports/payment-status", async (req, res) => {
  try {
    const result = await query(`
      SELECT payment_status, COUNT(payment_id) AS total_payments 
      FROM payment_tbl 
      GROUP BY payment_status
    `);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error fetching payment status report:", error);
    res.status(500).json({ error: "Failed to fetch payment report" });
  }
});

app.get("/admin/reports/services-status", async (req, res) => {
  try {
    const result = await query(`
      SELECT service_status, COUNT(service_id) AS total_services 
      FROM service_tbl 
      GROUP BY service_status
    `);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error fetching services status report:", error);
    res.status(500).json({ error: "Failed to fetch services report" });
  }
});

app.get("/admin/reports/top-products", async (req, res) => {
  try {
    const result = await query(`
      SELECT 
        p.product_name, 
        COUNT(od.order_id) AS total_orders 
      FROM order_details_tbl od
      JOIN product_tbl p ON od.product_id = p.product_id 
      GROUP BY p.product_name 
      ORDER BY total_orders DESC 
      LIMIT 9;
    `);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error fetching top products report:", error);
    res.status(500).json({ error: "Failed to fetch top products report" });
  }
});

app.get("/admin/reports/feedback", async (req, res) => {
  try {
    const result = await query(`
      SELECT rating, COUNT(feedback_id) AS total_feedback 
      FROM feedback_tbl 
      GROUP BY rating
    `);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error fetching feedback report:", error);
    res.status(500).json({ error: "Failed to fetch feedback report" });
  }
});

app.get("/admin/reports/recent-orders", async (req, res) => {
  try {
    const result = await query(`
      SELECT 
      o.order_id, 
      o.user_id, 
      p.product_name, 
      od.quantity, 
      o.order_status, 
      o.order_date 
      FROM order_tbl o
      JOIN order_details_tbl od ON o.order_id = od.order_id 
      JOIN product_tbl p ON od.product_id = p.product_id 
      ORDER BY o.order_date DESC 
      LIMIT 9;
    `);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error fetching recent orders report:", error);
    res.status(500).json({ error: "Failed to fetch recent orders report" });
  }
});

app.get("/admin/reports/service-requests", async (req, res) => {
  try {
    const result = await query(`
      SELECT service_type, COUNT(service_id) AS total_requests 
      FROM service_tbl 
      GROUP BY service_type
    `);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error fetching service requests report:", error);
    res.status(500).json({ error: "Failed to fetch service requests report" });
  }
});

app.listen(PORT, () => {
  console.log(`Server Started at ${PORT}`);
});
