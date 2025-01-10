import dotenv from "dotenv";
dotenv.config();
import express from "express";
import bodyParser from "body-parser";
import mysql from "mysql2";
import cors from "cors";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import jwt, { decode } from "jsonwebtoken";

const salt = 10;
const app = express();
const PORT = process.env.PORT;

app.use(express.json());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: ["http://localhost:3001", "http://localhost:3000"],
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
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Connect to the database
pool.getConnection((err, connection) => {
  if (err) {
    console.error("Database connection failed:", err.message);
  } else {
    console.log("Connected to the MySQL database.");
    connection.release(); // Release the connection back to the pool
  }
});

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
  const sql =
    "INSERT INTO user_tbl(user_type, first_name, last_name, email, phone_number, company_name, company_address, address_city, address_state, address_country, pincode, GST_no, user_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

  bcrypt.hash(req.body.user_password.toString(), salt, (err, hash) => {
    if (err) {
      console.error("Hashing Error:", err);
      return res.json({ Error: "Error while hashing password!" });
    }

    const values = [
      req.body.user_type,
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
    ];

    pool.query(sql, values, (err, result) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          res
            .status(409)
            .json({ status: "Error", message: "Email already Exists" });
        }
        console.error("SQL Error:", err);
        return res.json({ Error: "Error inserting data in server" });
      }

      return res.json({ status: "Success" });
    });
  });
});

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
            const token = jwt.sign({ name, user_id }, process.env.JWT_SECRET, {
              expiresIn: "7d",
            });
            res.cookie("token", token);
            return res.json({ status: "Success" });
          } else {
            return res.json({ message: "Password does not match!" });
          }
        }
      );
    } else {
      return res.json({ message: "Email not found, Please Register!" });
    }
  });
});

app.get("/profile", verifyUser, (req, res) => {
  const sql = "SELECT * FROM user_tbl WHERE first_name = ?";
  pool.query(sql, [req.name], (err, data) => {
    if (err) {
      console.error("SQL Error:", err);
      return res.json({ Error: "Error fetching user profile data" });
    }
    if (data.length > 0) {
      // Exclude sensitive data like password from the response
      const userProfile = {
        user_type: data[0].user_type,
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

// Add a new category (Admin Access Only)
app.post("/categories", verifyUser, async (req, res) => {
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
app.get("/products", (req, res) => {
  const sql = "SELECT * FROM product_tbl";
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
app.post("/products", verifyUser, async (req, res) => {
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
  const { feedback_text, feedback_rating } = req.body;
  if (
    !feedback_text ||
    !feedback_rating ||
    feedback_rating < 1 ||
    feedback_rating > 5
  )
    return res.status(400).json({ error: "Invalid feedback or rating" });
  const sql =
    "INSERT INTO feedback_tbl (product_id, feedback_text, feedback_rating, user_id) VALUES (?, ?, ?, ?)";
  pool.query(
    sql,
    [productId, feedback_text, feedback_rating, req.user_id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res
        .status(201)
        .json({
          message: "Feedback submitted successfully",
          feedbackId: result.insertId,
        });
    }
  );
});

// Get feedback for a product (Public Access)
app.get("/products/:productId/feedback", (req, res) => {
  const { productId } = req.params;
  const sql =
    "SELECT * FROM feedback_tbl WHERE product_id = ? ORDER BY feedback_date DESC";
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

  let connection;

  console.log("Request body:", req.body);

  try {
    // Start transaction
    connection = await beginTransaction();

    // Insert into `order_tbl`
    const orderResult = await query(
      "INSERT INTO order_tbl (user_id, order_status) VALUES (?, ?)",
      [req.user_id, "Pending"]
    );
    // console.log("User ID:", req.user_id); // Log the value of user_id
    const orderId = orderResult.insertId;

    // Insert into `order_details_tbl`
    await query(
      `
      INSERT INTO order_details_tbl 
      (order_id, product_id, quantity, no_of_ends, creel_type, creel_pitch, bobin_length)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
      [
        orderId,
        product_id,
        quantity,
        no_of_ends,
        creel_type,
        creel_pitch,
        bobin_length,
      ]
    );

    // Commit transaction
    await commitTransaction(connection);

    // Generate WhatsApp notification URL
    const ownerNumber = "917041177240"; // Replace with owner's WhatsApp number
    const message = encodeURIComponent(`
      New Order Placed!
      Order ID: ${orderId}
      Product ID: ${product_id}
      Quantity: ${quantity}
      Specifications:
      - No. of Ends: ${no_of_ends}
      - Creel Type: ${creel_type}
      - Creel Pitch: ${creel_pitch}
      - Bobin Length: ${bobin_length}
    `);
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
    // Fetch orders for the logged-in user
    const orders = await query(
      `
      SELECT o.order_id, o.order_status, od.product_id, od.quantity, od.no_of_ends, 
             od.creel_type, od.creel_pitch, od.bobin_length 
      FROM order_tbl o
      JOIN order_details_tbl od ON o.order_id = od.order_id
      WHERE o.user_id = ?
      `,
      [req.user_id] // assuming req.user_id is the logged-in user's ID
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

app.listen(PORT, () => {
  console.log(`Server Started at ${PORT}`);
});
