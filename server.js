import dotenv from "dotenv";
dotenv.config();
import express from "express";
import bodyParser from 'body-parser';
import mysql from 'mysql2';
import cors from "cors";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";

const salt = 10;
const app = express();
const PORT = process.env.PORT;

app.use(express.json());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: ["http://localhost:3001", "http://localhost:3000"],
  methods: ['GET', 'POST'],
  credentials: true
}));
app.use(cookieParser());

const db = mysql.createConnection({
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.DATABASE,
});

// Connect to the database
db.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err.message);
  } else {
    console.log('Connected to the MySQL database.');
  }
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

    db.query(sql, values, (err, result) => {
      if (err) {
        if(err.code === 'ER_DUP_ENTRY') {
          res.status(409).json({ status: "Error", message: "Email already Exists" });
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
  db.query(sql, [req.body.email], (err, data) => {
    if(err) {
      return res.json({ Error: "Error Login in server!" });
    }
    if(data.length > 0) {
      bcrypt.compare(req.body.user_password.toString(), data[0].user_password, (err, response) => {
        if(err) {
          return res.json({ Error: "Password compare error" });
        }
        if(response){
          const name = data[0].email;
          const token = jwt.sign({ name }, process.env.JWT_SECRET, {expiresIn: "7d"});
          res.cookie('token', token);
          return res.json({ status: "Success"});
        }
        else {
          return res.json({ message: "Password does not match!"});
        }
      })
    }
    else {
      return res.json({ Error: "Email not found, Please Register!" });
    }
  })
})

app.listen(PORT, () => {
  console.log(`Server Started at ${PORT}`);
});
