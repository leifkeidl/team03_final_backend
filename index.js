// COPY PASTED FROM ACTIVITY 21
// NEEDS CHANGES

import { MongoClient } from "mongodb";
import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
const app = express();
// Middleware
app.use(cors());
app.use(express.json());

// ======== CONFIG FOR JWT ========
const SECRET_KEY = "URMOM_URDAD_URDOG"; // use env var in real apps
const ACCESS_TOKEN_EXPIRE_MINUTES = 30; // set 1 for demos if you want

// MongoDB
// Server configuration
dotenv.config();
const PORT = process.env.PORT ?? 8081;
const HOST = process.env.HOST ?? "0.0.0.0";
// MongoDB configuration
const MONGO_URI = process.env.MONGO_URI;
const DBNAME = process.env.DBNAME;
const collection = process.env.COLLECTION;
const client = new MongoClient(MONGO_URI);
const db = client.db(DBNAME);


// Helper: save user
function saveUserToDb(email, hashedPw) {
    fakeUsersDb[email] = hashedPw;
    console.log("DB state:", fakeUsersDb); // debugging
}
// Helper: get user
function getUserByEmail(email) {
    const hashedPw = fakeUsersDb[email];
    if (!hashedPw) return null;
    return { email, hashedPassword: hashedPw };
}


app.post("/signup", async (req, res) => {
    try {
        const { email, password } = req.body;
        // Basic validation
        if (!email || !password) {
            return res.status(400).json({ detail: "email and password are required" });
        }
        // Check if user exists
        if (fakeUsersDb[email]) {
            console.log(`User ${email} already exists`);
            return res.status(400).json({ detail: "User already exists" });
        }
        console.log("New user:", email, password); // debugging (don't do this in prod)
        // Hash password with bcrypt
        const hashedPw = await bcrypt.hash(password, 10); // 10 = salt rounds
        saveUserToDb(email, hashedPw);
        return res.json({ msg: "signup ok" });
    } catch (err) {
        console.error("Error in /signup:", err);
        return res.status(500).json({ detail: "Internal server error" });
    }
});


// ======== 2) LOGIN ========
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ detail: "email and password are required" });
        }
        const dbUser = getUserByEmail(email);
        if (!dbUser) {
            return res.status(401).json({ detail: "Invalid credentials-User" });
        }
        const validPassword = await bcrypt.compare(password, dbUser.hashedPassword);
        if (!validPassword) {
            return res.status(401).json({ detail: "Invalid credentials-Password" });
        }
        // sub = subject (usually the user id or email)
        const token = jwt.sign(
            { sub: dbUser.email },
            SECRET_KEY,
            { expiresIn: `${ACCESS_TOKEN_EXPIRE_MINUTES}m` } // e.g. "30m"
        );
        console.log("Token:", token);
        console.log("DB:", fakeUsersDb);
        return res.json({ token }); // shape { "token": "<JWT>" }
    } catch (err) {
        console.error("Error in /login:", err);
        return res.status(500).json({ detail: "Internal server error" });
    }
});


// ======== 3) JWT AUTH MIDDLEWARE (like get_current_user) ========
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
        return res.status(401).json({ detail: "Missing Authorization header" });
    }
    const [scheme, token] = authHeader.split(" ");
    if (scheme !== "Bearer" || !token) {
        return res.status(401).json({ detail: "Invalid Authorization header" });
    }
    jwt.verify(token, SECRET_KEY, (err, payload) => {
        if (err) {
            if (err.name === "TokenExpiredError") {
                return res.status(401).json({ detail: "Token expired" });
            }
            return res.status(401).json({ detail: "Invalid token" });
        }
        const email = payload.sub;
        if (!email) {
            return res.status(401).json({ detail: "Invalid token payload" });
        }
        const user = getUserByEmail(email);
        if (!user) {
            return res.status(401).json({ detail: "User not found" });
        }
        // Attach to request so protected route can use it
        req.userEmail = email;
        next();
    });
}


// ======== 4) PROTECTED ROUTE ========
app.get("/protected", authenticateToken, (req, res) => {
    return res.json({ msg: `Hello ${req.userEmail}, this is protected data!` });
});




// ======== SIMPLE ROOT FOR QUICK TESTING ========
app.get("/hello", (req, res) => {
    res.json({ message: "Hello from NodeJS/Express" });
});
// ======== START SERVER ========
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

// test
app.get("/dishes", async (req, res) => {

    await client.connect();
    console.log("Node connected successfully to GET MongoDB");

    const query = {};
    const results = await db
        .collection(collection)
        .find(query)
        .limit(100)
        .toArray();
    console.log(results);

    res.status(200);
    // res.send(results);
    res.json(results);


});
