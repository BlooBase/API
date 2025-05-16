const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const path = require('path');
const multer = require('multer'); // For handling file uploads
const crypto = require('crypto');
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
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET, // Add your storage bucket URL here

});

const db = admin.firestore();
const authAdmin = admin.auth();
const storageAdmin = admin.storage(); // Get the Storage service from Admin SDK


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

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const folder = req.body.folder || 'uploads'; // Get folder from request body
    const uploadPath = path.join(__dirname, 'uploads', folder);
    // Ensure directory exists
    require('fs').mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  },
});

const upload = multer({ storage });

// --- User Management Endpoints ---
app.post('/api/users', authenticate, async (req, res) => {
  try {
    const { userId, email, name, role, authProvider } = req.body;
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

app.get('/api/users/:userId', authenticate, async (req, res) => {
  try {
    const userId = req.params.userId;
    if (req.user.uid !== userId) {
      return res.status(403).json({ error: 'Forbidden: Cannot access other user data' });
    }
    const userDoc = await db.collection('Users').doc(userId).get();
    if (userDoc.exists) {
      res.status(200).json({ ...userDoc.data(), role: req.user.role });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error('Error getting user data:', error);
    res.status(500).json({ error: 'Failed to get user data', details: error.message });
  }
});

app.patch('/api/users/:userId', authenticate, async (req, res) => {
  try {
    const userId = req.params.userId;
    if (req.user.uid !== userId) {
      return res.status(403).json({ error: 'Forbidden: Cannot update other user data' });
    }
    const { name, email } = req.body;
    const updates = {};
    if (name) updates.Name = name;
    if (email) updates.Email = email;

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

app.delete('/api/users/:userId', authenticate, async (req, res) => {
  try {
    const userId = req.params.userId;
    if (req.user.uid !== userId) {
      return res.status(403).json({ error: 'Forbidden: Cannot delete other user accounts' });
    }
    await db.collection('Users').doc(userId).delete();
    res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user', details: error.message });
  }
});

// --- Utility Endpoints ---
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

// --- Seller Card Endpoints ---
app.post('/api/upload', authenticate, upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No image file uploaded' });
  }
  const filePath = path.join(req.body.folder || 'uploads', req.file.filename);
  res.status(200).json({ path: filePath }); // Return the server-side path
});

app.post('/api/sellers/card', authenticate, async (req, res) => {
  try {
    const { image, color, description, genre, textColor, title } = req.body;
    const sellerDocRef = db.collection('Sellers').doc(req.user.uid);
    await sellerDocRef.set({
      image: image, // Store the path received from /api/upload
      color,
      description,
      genre,
      textColor,
      title,
      userId: req.user.uid, // Ensure consistency
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });
    res.status(200).json({ message: 'Seller card updated successfully' });
  } catch (error) {
    console.error('Error updating seller card:', error);
    res.status(500).json({ error: 'Failed to update seller card', details: error.message });
  }
});

app.get('/api/sellers/card', authenticate, async (req, res) => {
  try {
    const sellerDoc = await db.collection('Sellers').doc(req.user.uid).get();
    if (sellerDoc.exists) {
      res.status(200).json(sellerDoc.data());
    } else {
      res.status(404).json({ error: 'Seller card not found' });
    }
  } catch (error) {
    console.error('Error getting seller card:', error);
    res.status(500).json({ error: 'Failed to get seller card', details: error.message });
  }
});

app.delete('/api/sellers/card', authenticate, async (req, res) => {
  try {
    // Logic to delete associated products
    const productsRef = db.collection('Products');
    const q = productsRef.where('SellerID', '==', req.user.uid);
    const snapshot = await q.get();
    const batch = db.batch();
    snapshot.forEach(doc => {
      batch.delete(db.collection('Products').doc(doc.id));
    });
    await batch.commit();

    // Delete the seller card
    await db.collection('Sellers').doc(req.user.uid).delete();
    res.status(200).json({ message: 'Seller card deleted successfully' });
  } catch (error) {
    console.error('Error deleting seller card:', error);
    res.status(500).json({ error: 'Failed to delete seller card', details: error.message });
  }
});

app.get('/api/sellers/products', authenticate, async (req, res) => {
  try {
    const productsRef = db.collection('Products');
    const q = productsRef.where('SellerID', '==', req.user.uid);
    const snapshot = await q.get();
    const products = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.status(200).json(products);
  } catch (error) {
    console.error('Error getting seller products:', error);
    res.status(500).json({ error: 'Failed to get seller products', details: error.message });
  }
});

// --- Product Endpoints ---
app.post('/api/products', authenticate, async (req, res) => {
  try {
    const { Seller, SellerID, image, name, price, stock } = req.body;
    const newProductRef = db.collection('Products').doc();
    await newProductRef.set({
      Seller,
      SellerID,
      image, // Store the path
      name,
      price,
      stock,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    res.status(201).json({ message: 'Product added successfully', id: newProductRef.id });
  } catch (error) {
    console.error('Error adding product:', error);
    res.status(500).json({ error: 'Failed to add product', details: error.message });
  }
});

app.patch('/api/products/:productId', authenticate, async (req, res) => {
  try {
    const { image, name, price } = req.body;
    const productId = req.params.productId;
    const updates = {};
    if (image) updates.image = image;
    if (name) updates.name = name;
    if (price) updates.price = price;
    updates.updatedAt = admin.firestore.FieldValue.serverTimestamp();

    await db.collection('Products').doc(productId).update(updates);
    res.status(200).json({ message: 'Product updated successfully' });
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({ error: 'Failed to update product', details: error.message });
  }
});

app.delete('/api/products/:productId', authenticate, async (req, res) => {
  try {
    const productId = req.params.productId;
    await db.collection('Products').doc(productId).delete();
    res.status(200).json({ message: 'Product deleted successfully' });
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ error: 'Failed to delete product', details: error.message });
  }
});

// --- Cart Endpoints ---
app.post('/api/cart/add', authenticate, async (req, res) => {
  try {
    const { productId } = req.body;
    const userId = req.user.uid;
    const cartRef = db.collection('Carts').doc(userId);
    const productDoc = await db.collection('Products').doc(productId).get();

    if (!productDoc.exists) {
      return res.status(404).json({ error: 'Product not found' });
    }
    const productData = productDoc.data();

    await db.runTransaction(async (transaction) => {
      const cartSnapshot = await transaction.get(cartRef);
      if (cartSnapshot.exists) {
        const cart = cartSnapshot.data();
        const existingItemIndex = (cart.items || []).findIndex(item => item.id === productId);
        if (existingItemIndex > -1) {
          const updatedItems = [...cart.items];
          updatedItems[existingItemIndex] = {
            ...updatedItems[existingItemIndex],
            quantity: (updatedItems[existingItemIndex].quantity || 0) + 1,
          };
          transaction.update(cartRef, { items: updatedItems });
        } else {
          transaction.update(cartRef, {
            items: admin.firestore.FieldValue.arrayUnion({
              id: productId,
              name: productData.name,
              price: productData.price,
              image: productData.image, // Assuming you want to store the image path
              Seller: productData.Seller,
              quantity: 1,
            }),
          });
        }
      } else {
        transaction.set(cartRef, {
          items: [{
            id: productId,
            name: productData.name,
            price: productData.price,
            image: productData.image,
            Seller: productData.Seller,
            quantity: 1,
          }],
        });
      }
    });

    res.status(200).json({ message: 'Product added to cart' });
  } catch (error) {
    console.error('Error adding to cart:', error);
    res.status(500).json({ error: 'Failed to add to cart', details: error.message });
  }
});

app.post('/api/cart/remove', authenticate, async (req, res) => {
  try {
    const { productId } = req.body;
    const userId = req.user.uid;
    const cartRef = db.collection('Carts').doc(userId);

    await db.runTransaction(async (transaction) => {
      const cartSnapshot = await transaction.get(cartRef);
      if (cartSnapshot.exists()) {
        const cart = cartSnapshot.data();
        const updatedItems = (cart.items || []).filter(item => item.id !== productId);
        transaction.update(cartRef, { items: updatedItems });
      }
    });

    res.status(200).json({ message: 'Product removed from cart' });
  } catch (error) {
    console.error('Error removing from cart:', error);
    res.status(500).json({ error: 'Failed to remove from cart', details: error.message });
  }
});

app.get('/api/cart', authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;
    const cartDoc = await db.collection('Carts').doc(userId).get();
    if (cartDoc.exists) {
      res.status(200).json(cartDoc.data().items || []);
    } else {
      res.status(200).json(cartDoc.data().items || []);
    }
  } catch (error) {
    console.error('Error retrieving cart:', error);
    res.status(500).json({ error: 'Failed to retrieve cart', details: error.message });
  }
});

// --- Public Endpoints ---
app.get('/api/products', async (req, res) => {
  try {
    const snapshot = await db.collection('Products').get();
    const productsWithUrls = await Promise.all(
      snapshot.docs.map(async (doc) => {
        const data = doc.data();
        let imageUrl = null;
        if (data.image) {
          try {
            const bucket = storageAdmin.bucket();
            const file = bucket.file(data.image);
            const [url] = await file.getSignedUrl({
              action: 'read',
              expires: Date.now() + 60 * 60 * 1000, // URL expires in 1 hour
            });
            imageUrl = url;
          } catch (error) {
            console.error(`Error fetching image URL for product ${doc.id}:`, error);
            // Optionally handle the error
          }
        }
        return {
          id: doc.id,
          ...data,
          imageUrl,
        };
      })
    );
    res.status(200).json(productsWithUrls);
  } catch (error) {
    console.error('Error retrieving products with image URLs:', error);
    res.status(500).json({ error: 'Failed to retrieve products with image URLs', details: error.message });
  }
});

app.get('/api/sellers/:sellerId/products', async (req, res) => {
  try {
    const sellerId = req.params.sellerId;
    const productsRef = db.collection('Products');
    const q = productsRef.where('SellerID', '==', sellerId);
    const snapshot = await q.get();
    const products = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.status(200).json(products);
  } catch (error) {
    console.error(`Error retrieving products for seller ${sellerId}:`, error);
    res.status(500).json({ error: `Failed to retrieve products for seller ${sellerId}`, details: error.message });
  }
});

app.get('/api/sellers', async (req, res) => {
  try {
    const snapshot = await db.collection('Sellers').get();
    const sellers = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.status(200).json(sellers);
  } catch (error) {
    console.error('Error retrieving sellers:', error);
    res.status(500).json({ error: 'Failed to retrieve sellers', details: error.message });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend is running on port ${PORT}`);
});