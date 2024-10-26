const dotenv = require('dotenv')
dotenv.config();
const express = require('express');
const router = express.Router();

const { ObjectId } = require('mongodb');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fetchUser = require('../middleware/fetchUser');


const JWT_SECRET = process.env.JWT_SECRET;
const connectToDb = require('../server'); // Import the connectToDb function

// ROUTE 1 = Create a User using: POST "/api/auth/createuser". No login required
router.post('/createuser', [
    body('username', 'Username must contain at least 5 characters').isLength({ min: 5 }),
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password must be at least 8 characters').isLength({ min: 8 })
], async (req, res) => {
    let success = false;

    // If there are validation errors, return error and Bad request
    let errors = validationResult(req).array();
    if (errors.length !== 0) {
        return res.status(400).json({ errors });
    }

    try {
        const db = await connectToDb();

        // Check if user with the same email already exists
        let user = await db.collection('users').findOne({ email: req.body.email });
        if (user) {
            errors.push({ "msg": "Sorry, another account exists with this email!" })
            return res.status(400).json({ success, errors });
        }

        // Generate hash for the password
        const salt = await bcrypt.genSalt(10);
        const secPass = await bcrypt.hash(req.body.password, salt);

        user = await db.collection('users').insertOne({
            username: req.body.username,
            email: req.body.email,
            password: secPass,
            createdAt: new Date()
        });

        // Create JWT token
        const data = {
            user: {
                id: user.insertedId
            }
        };
        const authToken = jwt.sign(data, JWT_SECRET);

        res.status(201).json({ success: true, authToken });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Internal Server Error");
    }
});

// ROUTE 2 = Login for existing User using: POST "/api/auth/login". No login required
router.post('/login', [
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password cannot be blank').exists()
], async (req, res) => {
    let success = false;

    // If there are validation errors, return error and Bad request
    const errors = validationResult(req).array();
    if (errors.length !== 0) {
        return res.status(400).json({ errors });
    }

    const { email, password } = req.body;

    try {
        const db = await connectToDb();

        // Find the user by email
        let user = await db.collection('users').findOne({ email });
        if (!user) {
            errors.push({ "msg": "User does not exist" })
            return res.status(400).json({ success, errors });
        }

        // Compare the provided password with the hashed password stored in the database
        const passwordCompare = await bcrypt.compare(password, user.password);
        if (!passwordCompare) {
            errors.push({ "msg": "Please login with valid credentials" })
            return res.status(400).json({ success, errors });
        }

        //Logic to manitain last login timestamp
        await db.collection('users').updateOne(
            { _id: user._id },
            { $set: { lastLogin: new Date() } }
        );

        // Create JWT token
        const payload = {
            user: {
                id: user._id
            }
        };
        const authToken = jwt.sign(payload, JWT_SECRET);
        res.json({ success: true, authToken });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Internal Server Error");
    }
});

// ROUTE 3 = Get logged in user details using: POST "/api/auth/getuser"
router.post('/getuser', fetchUser, async (req, res) => {
    try {
        const db = await connectToDb();

        // Find the user by ID and exclude the password field
        const userID = req.user.id;
        const user = await db.collection('users').findOne({ _id: new ObjectId(userID) }, { projection: { password: 0 } });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Internal Server Error");
    }
});

// ROUTE 4 = Change password for user. POST /api/auth/changepassword
router.post('/changepassword', fetchUser, [
    body('newPassword', 'Password must be at least 8 characters').isLength({ min: 8 })
], async (req, res) => {
    let success = false;
    const errors = validationResult(req).array();
    if (errors.length !== 0) {
        return res.status(400).json({ success, errors });
    }
    const { newPassword } = req.body;

    try {
        const db = await connectToDb();
        // Compare the provided password with the hashed password stored in the database
        const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) });
        const passwordCompare = await bcrypt.compare(newPassword, user.password);
        if (passwordCompare) {
            errors.push({ "msg": "New master password must be different from old master password" })
            return res.status(400).json({ success, errors });
        }

        // Generate hash for the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update user's password
        await db.collection('users').findOneAndUpdate(
            { _id: new ObjectId(req.user.id) },
            { $set: { password: hashedPassword } },
            { returnDocument: 'after' }
        );

        res.status(200).json({ success: true, message: 'Password updated successfully! Please login with updated credentials' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ROUTE 5 = Deleting user. POST /api/auth/deleteuser
router.post('/deleteuser', fetchUser, async (req, res) => {
    try {
        const userId = req.user.id; // Get the user ID from the request object set by the middleware
        const db = await connectToDb();

        // Delete associated passwords
        await db.collection('passwords').deleteMany({ user: new ObjectId(userId) });

        // Delete user
        await db.collection('users').deleteOne({ _id: new ObjectId(userId) });

        return res.status(200).json({ success: true, message: 'User and associated passwords deleted successfully.' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

module.exports = router;
