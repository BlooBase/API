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
const authAdmin = admin.auth(); // To access Firebase Auth admin methods

// Authentication Middleware
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
  }

  const idToken = authHeader.split(' ')[1];

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken; // Add user info to the request object
    next();
  } catch (error) {
    console.error('Error verifying ID token:', error);
    return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
};

// Optional Authorization Middleware (Example - Role-based)
const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
    }
    next();
  };
};

// Add a new user
app.post('/api/users', authenticate, async (req, res) => {
  try {
    const { userId, email, name, role, authProvider } = req.body;
    // You might want to verify if the userId from the client matches the uid from the token
    if (req.user.uid !== userId) {
      return res.status(403).json({ error: 'Forbidden: User ID mismatch' });
    }
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
app.get('/api/users/:userId', authenticate, async (req, res) => {
  try {
    const userId = req.params.userId;
    // Ensure the requested userId matches the authenticated user's uid
    if (req.user.uid !== userId) {
      return res.status(403).json({ error: 'Forbidden: Cannot access other user data' });
    }
    const userDoc = await db.collection('Users').doc(userId).get();
    if (userDoc.exists) {
      // Add the role to the response if needed
      res.status(200).json({ ...userDoc.data(), role: req.user.role });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error('Error getting user data:', error);
    res.status(500).json({ error: 'Failed to get user data', details: error.message });
  }
});

// Update user info name and email
app.patch('/api/users/:userId', authenticate, async (req, res) => {
  try {
    const userId = req.params.userId;
    // Ensure the user can only update their own data
    if (req.user.uid !== userId) {
      return res.status(403).json({ error: 'Forbidden: Cannot update other user data' });
    }
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
app.delete('/api/users/:userId', authenticate, async (req, res) => {
  try {
    const userId = req.params.userId;
    // Ensure the user can only delete their own account (or an admin can)
    if (req.user.uid !== userId) {
      return res.status(403).json({ error: 'Forbidden: Cannot delete other user accounts' });
    }
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
app.get('/api/roles/:roleName/size', authenticate, authorizeRole(['admin']), async (req, res) => {
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
app.get('/api/collections/:collectionName/size', authenticate, authorizeRole(['admin']), async (req, res) => {
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