const express = require('express');
const router = express.Router();
const fetchUser = require('../middleware/fetchUser');
const { ObjectId } = require('mongodb');
const connectToDb = require('../server'); // Import connectToDb function
const { encrypt, decrypt } = require('../utils/encryption'); // Import the encryption/decryption functions

// Helper function to get the passwords collection
const getPasswordsCollection = async () => {
    const db = await connectToDb();
    return db.collection('passwords');
};


// ROUTE 1 = Get all passwords: GET "/api/passwords/fetchallpass". login required
router.get('/fetchallpass', fetchUser, async (req, res) => {
    try {
        const passwordsCollection = await getPasswordsCollection();
        const passwords = await passwordsCollection.find({ user: new ObjectId(req.user.id) }).toArray();

        if (passwords.length===0)
            return res.send("No passwords to display")

        // Decrypt the passwords before sending to the client
        const decryptedPasswords = passwords.map(pass => ({
            ...pass,
            password: decrypt({ iv: pass.iv, encryptedData: pass.password })
        }));

        res.send(decryptedPasswords);
    } catch (error) {
        console.log(error.message);
        res.status(500).send("Internal Server Error");
    }
});

// ROUTE 2 = Add passwords: POST "/api/passwords/addpass". login required
router.post('/addpass', fetchUser, async (req, res) => {
    try {
        const { url, username, password } = req.body;
        const passwordsCollection = await getPasswordsCollection();

        const { iv, encryptedData } = encrypt(password);

        const pass = {
            url,
            username,
            password: encryptedData, // Store the encrypted password
            iv: iv.toString('hex'),
            user: new ObjectId(req.user.id)
        };

        const result = await passwordsCollection.insertOne(pass);
        res.json(pass);
    } catch (error) {
        console.log(error.message);
        res.status(500).send("Internal Server Error");
    }
});

// ROUTE 3 = Update existing passwords: PUT "/api/passwords/updatepass/:id". login required
router.put('/updatepass/:id', fetchUser, async (req, res) => {
    try {
        const { url, username, password } = req.body;
        const passwordsCollection = await getPasswordsCollection();

        
        const newPass = {};
        if (url) newPass.url = url;
        if (username) newPass.username = username;
        const { iv, encryptedData } = encrypt(password);
        newPass.iv = iv;
        newPass.password = encryptedData

        // Find the password to be updated
        const pass = await passwordsCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!pass) {
            return res.status(404).send("Password not found");
        }

        // Check if the user is authorized to update the password
        if (pass.user.toString() !== req.user.id) {
            return res.status(401).send("Not authorized");
        }

        const updatedPass = await passwordsCollection.findOneAndUpdate(
            { _id: new ObjectId(req.params.id) },
            { $set: newPass },
            { returnDocument: 'after' }
        );

        res.json(updatedPass);
    } catch (error) {
        console.log(error.message);
        res.status(500).send("Internal Server Error");
    }
});

// ROUTE 4 = Delete existing passwords: DELETE "/api/passwords/deletepass/:id". login required
router.delete('/deletepass/:id', fetchUser, async (req, res) => {
    try {
        const passwordsCollection = await getPasswordsCollection();

        const pass = await passwordsCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!pass) {
            return res.status(404).send("Password entry not found");
        }

        if (pass.user.toString() !== req.user.id) {
            return res.status(401).send("Not authorized");
        }

        await passwordsCollection.deleteOne({ _id: new ObjectId(req.params.id) });

        res.json({ message: "Password deleted successfully", deletedPass: pass });
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal Server Error");
    }
});

module.exports = router;
