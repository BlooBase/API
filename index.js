const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
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


app.post('/api/users',  async (req, res) => {
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
app.get('/api/roles/:roleName/size', authenticate, async (req, res) => {
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

app.get('/api/collections/:collectionName/size', authenticate, async (req, res) => {
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


// --- Seller and Card Endpoints ---
app.delete('/api/seller/card', authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;

    // 1. Find all products for this seller
    const productsRef = db.collection("Products");
    const q = productsRef.where("SellerID", "==", userId);
    const snapshot = await q.get();

    // 2. Delete each product
    const batchDeletes = [];
    snapshot.forEach((docSnap) => {
      batchDeletes.push(db.collection("Products").doc(docSnap.id).delete());
    });
    await Promise.all(batchDeletes);

    // 3. Delete the seller card
    await db.collection("Sellers").doc(userId).delete();

    res.status(200).json({ message: "Seller card and products deleted successfully." });
  } catch (error) {
    console.error("Error deleting seller card:", error);
    res.status(500).json({ error: "Failed to delete seller card", details: error.message });
  }
});
app.post('/api/seller/card', authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { color, description, genre, image, textColor, title } = req.body;

    if (!color || !description || !genre || !image || !textColor || !title) {
      return res.status(400).json({ error: 'Missing required seller card data.' });
    }

    const sellerCardData = {
      color,
      description,
      genre,
      image, // This is the Firebase Storage path
      textColor,
      title,
      userId: userId, // Associate the card with the user
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    // Check if a seller card already exists for this user
    const sellerCardRef = db.collection('Sellers').doc(userId);
    const docSnapshot = await sellerCardRef.get();

    if (docSnapshot.exists) {
      // Update existing card
      await sellerCardRef.update(sellerCardData);
      res.status(200).json({ message: 'Seller card updated successfully.' });
    } else {
      // Create a new card with the user ID as the document ID
      await sellerCardRef.set(sellerCardData);
      res.status(201).json({ message: 'Seller card created successfully.' });
    }
  } catch (error) {
    console.error('Error creating/updating seller card:', error);
    res.status(500).json({ error: 'Failed to create/update seller card', details: error.message });
  }
});
app.post('/api/sellers', authenticate, async (req, res) => {
  try {
    const {
      color,
      description,
      genre,
      image,       // Already-uploaded image path from Firebase Storage
      textColor,
      title
    } = req.body;

    if (!color || !description || !genre || !image || !textColor || !title) {
      return res.status(400).json({ error: 'Missing required seller data fields.' });
    }

    const sellerRef = db.collection('Sellers').doc(); // Let Firestore generate the ID
    await sellerRef.set({
      color,
      description,
      genre,
      image, // Assumes the image path was uploaded and passed in from client
      textColor,
      title,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(201).json({ message: 'Seller created successfully', id: sellerRef.id });
  } catch (error) {
    console.error('Failed to add seller:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});
app.get("/api/sellers", async (req, res) => {
  try {
    const snapshot = await db.collection("Sellers").get();
    const sellers = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
    }));
    res.status(200).json(sellers);
  } catch (error) {
    console.error("Failed to fetch sellers:", error);
    res.status(500).json({ error: "Failed to retrieve sellers", details: error.message });
  }
});


// --- Product Endpoints ---
app.post("/api/products", authenticate, async (req, res) => {
  try {
    const { image, name, price } = req.body;
    const userId = req.user.uid;

    // Fetch seller card
    const sellerDocRef = db.collection("Sellers").doc(userId);
    const sellerSnap = await sellerDocRef.get();

    let storeName = "Unknown Store";
    let storeGenre = "Unknown";

    if (sellerSnap.exists) {
      const sellerData = sellerSnap.data();
      storeName = sellerData.title || "Unknown Store";
      storeGenre = sellerData.genre || "Unknown";
    }

    // Add product
    const productsRef = db.collection("Products");
    await productsRef.add({
      Seller: storeName,
      SellerID: userId,
      image,
      name,
      price,
      genre: storeGenre,
      createdAt: new Date(),
    });

    res.status(200).json({ message: "Product added successfully." });
  } catch (error) {
    console.error("Error adding product:", error);
    res.status(500).json({ error: "Failed to add product", details: error.message });
  }
});
app.get("/api/products/seller", authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;

    const productsRef = db.collection("Products");
    const q = productsRef.where("SellerID", "==", userId);
    const snapshot = await q.get();

    const products = snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));

    res.status(200).json(products);
  } catch (error) {
    console.error("Error fetching seller products:", error);
    res.status(500).json({ error: "Failed to fetch seller products", details: error.message });
  }
});
app.put("/api/products/:id", authenticate, async (req, res) => {
  try {
    const productId = req.params.id;
    const { image, name, price } = req.body;

    const productRef = db.collection("Products").doc(productId);
    await productRef.update({
      image,
      name,
      price,
      updatedAt: new Date(),
    });

    res.status(200).json({ message: "Product updated successfully." });
  } catch (error) {
    console.error("Error updating product:", error);
    res.status(500).json({ error: "Failed to update product", details: error.message });
  }
});
app.delete("/api/products/:id", authenticate, async (req, res) => {
  try {
    const productId = req.params.id;

    await db.collection("Products").doc(productId).delete();

    res.status(200).json({ message: "Product deleted successfully." });
  } catch (error) {
    console.error("Error deleting product:", error);
    res.status(500).json({ error: "Failed to delete product", details: error.message });
  }
});
app.get("/api/seller/products", async (req, res) => {
  const { sellerId } = req.query;
  if (!sellerId) {
    return res.status(400).json({ error: "Missing sellerId" });
  }

  try {
    const productsRef = db.collection("Products");
    const querySnapshot = await productsRef.where("SellerID", "==", sellerId).get();

    const products = querySnapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.status(200).json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ error: "Failed to fetch products", details: error.message });
  }
});
app.get("/api/products", async (req, res) => {
  try {
    const snapshot = await db.collection("Products").get();
    const products = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
    }));

    res.status(200).json(products);
  } catch (error) {
    console.error("Failed to fetch products:", error);
    res.status(500).json({ error: "Failed to retrieve products", details: error.message });
  }
});



// --- Cart Endpoints ---
app.post("/api/cart/add", authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { id, name, price, imageUrl, Seller } = req.body;

    const cartRef = db.collection("Carts").doc(userId);
    const cartSnap = await cartRef.get();

    if (cartSnap.exists) {
      const cartData = cartSnap.data();
      const alreadyInCart = (cartData.items || []).some(item => item.id === id);

      if (!alreadyInCart) {
        await cartRef.update({
          items: admin.firestore.FieldValue.arrayUnion({
            id,
            name,
            price,
            imageUrl,
            Seller,
            quantity: 1
          })
        });
      }
    } else {
      await cartRef.set({
        items: [{
          id,
          name,
          price,
          imageUrl,
          Seller,
          quantity: 1
        }]
      });
    }

    res.status(200).json({ message: "Item added to cart" });
  } catch (error) {
    console.error("Error adding to cart:", error);
    res.status(500).json({ error: "Failed to add to cart", details: error.message });
  }
});
app.post("/api/cart/remove", authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { productId } = req.body;

    const cartRef = db.collection("Carts").doc(userId);
    const cartSnap = await cartRef.get();

    if (cartSnap.exists) {
      const cartData = cartSnap.data();
      const updatedItems = (cartData.items || []).filter(item => item.id !== productId);
      await cartRef.update({ items: updatedItems });

      res.status(200).json({ message: "Item removed", updatedItems });
    } else {
      res.status(200).json({ message: "Cart not found, nothing to remove", updatedItems: [] });
    }
  } catch (error) {
    console.error("Error removing from cart:", error);
    res.status(500).json({ error: "Failed to remove from cart", details: error.message });
  }
});
app.get("/api/cart/retrieve", authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;
    const cartRef = db.collection("Carts").doc(userId);
    const cartSnap = await cartRef.get();

    if (cartSnap.exists) {
      const data = cartSnap.data();
      res.status(200).json({ items: data.items || [] });
    } else {
      res.status(200).json({ items: [] });
    }
  } catch (error) {
    console.error("Error retrieving cart:", error);
    res.status(500).json({ error: "Failed to retrieve cart", details: error.message });
  }
});

// --- Sam Endpoints ---

// Add this to your Express app (after authenticate middleware is defined)
app.get('/api/seller/card', authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;
    const sellerDoc = await db.collection('Sellers').doc(userId).get();
    if (!sellerDoc.exists) {
      return res.status(404).json({ error: 'Seller card not found' });
    }
    res.status(200).json(sellerDoc.data());
  } catch (error) {
    console.error('Error fetching seller card:', error);
    res.status(500).json({ error: 'Failed to fetch seller card', details: error.message });
  }
});


// --- Public Endpoints ---


// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend is running on port ${PORT}`);
});