const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin SDK
const serviceAccount = JSON.parse(
  Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT, 'base64').toString()
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DB_URL,
});

const db = admin.firestore();

// Add a new user
app.post('/api/users', async (req, res) => {
  try {
    const { userId, email, name, role, authProvider } = req.body;
    const userData = {
      Email: email,
      Name: name,
      joinedAt: admin.firestore.FieldValue.serverTimestamp(),
      authProvider: authProvider,
      Role: role,
    };
    await db.collection('Users').doc(userId).set(userData);
    res.status(200).json({ message: 'User added successfully' });
  } catch (error) {
    console.error('Error adding user:', error);
    res.status(500).json({ error: 'Failed to add user', details: error.message });
  }
});

// Get user data by ID
app.get('/api/users/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const userDoc = await db.collection('Users').doc(userId).get();
    if (userDoc.exists) {
      res.status(200).json(userDoc.data());
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error('Error getting user data:', error);
    res.status(500).json({ error: 'Failed to get user data', details: error.message });
  }
});

// Update user info name and email
app.patch('/api/users/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const { name, email } = req.body;
    const updates = {};
    if (name) updates.Name = name;
    if (email) updates.Email = email; // Consider security implications of allowing email updates via API

    if (Object.keys(updates).length > 0) {
      await db.collection('Users').doc(userId).update(updates);
      res.status(200).json({ message: 'User data updated successfully' });
    } else {
      res.status(200).json({ message: 'No updates provided' });
    }
  } catch (error) {
    console.error('Error updating user data:', error);
    res.status(500).json({ error: 'Failed to update user data', details: error.message });
  }
});

//Delete user account
app.delete('/api/users/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    // You might want to add server-side checks or logging here
    await db.collection('Users').doc(userId).delete();
    // Optionally, you might want to also delete the associated Firebase Auth user
    // await authAdmin.deleteUser(userId);
    res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user', details: error.message });
  }
});



// Get the count of users with a specific role
app.get('/api/roles/:roleName/size', async (req, res) => {
  try {
    const roleName = req.params.roleName;
    const usersRef = db.collection('Users');
    const querySnapshot = await usersRef.where('Role', '==', roleName).count().get();
    res.status(200).json({ count: querySnapshot.data().count });
  } catch (error) {
    console.error(`Error getting size of role ${roleName}:`, error);
    res.status(500).json({ error: `Failed to get size of role ${roleName}`, details: error.message });
  }
});

// Get the size of a collection
app.get('/api/collections/:collectionName/size', async (req, res) => {
  try {
    const collectionName = req.params.collectionName;
    const collectionRef = db.collection(collectionName);
    const querySnapshot = await collectionRef.count().get();
    res.status(200).json({ count: querySnapshot.data().count });
  } catch (error) {
    console.error(`Error getting size of collection ${collectionName}:`, error);
    res.status(500).json({ error: `Failed to get size of collection ${collectionName}`, details: error.message });
  }
});


// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend is running on port ${PORT}`);
});
