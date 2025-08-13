import express from "express";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const app = express();
app.use(express.json());

// Serve index.html
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

// Store OTPs temporarily
const otps = {};

app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ message: "Email is required" });

  const otp = Math.floor(1000 + Math.random() * 9000);
  otps[email] = otp;

  try {
    let transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.EMAIL, pass: process.env.EMAIL_PASS }
    });

    await transporter.sendMail({
      from: process.env.EMAIL,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP is ${otp}`
    });

    res.json({ message: "OTP sent successfully!" });
  } catch (error) {
    res.json({ message: "Error sending OTP", error });
  }
});

app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  if (otps[email] && otps[email] == otp) {
    delete otps[email];
    return res.json({ success: true, message: "OTP verified!" });
  }
  res.json({ success: false, message: "Invalid OTP" });
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
