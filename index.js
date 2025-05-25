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


/**
 * Middleware to authenticate requests using Firebase ID tokens.
 * It expects a 'Bearer' token in the 'Authorization' header.
 * If the token is valid, it decodes it and attaches the user information to `req.user`.
 * Otherwise, it returns a 401 Unauthorized error.
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object.
 * @param {function} next - The next middleware function.
 * @returns {void}
 */
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
  }

  const idToken = authHeader.split(' ')[1];

  try {
    // Verify the Firebase ID token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    // Attach the decoded token (containing user information like UID) to the request object
    req.user = decodedToken;
    next(); // Proceed to the next middleware or route handler
  } catch (error) {
    console.error('Error verifying ID token:', error);
    return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
};

//--- User Endpoints---
/**
 * Handles POST requests to add a new user to Firestore.
 * Requires authentication and ensures the requesting user's ID matches the provided userId.
 * @param {object} req - The Express request object, expecting `userId`, `email`, `name`, `role`, and `authProvider` in the body.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
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

/**
 * Handles GET requests to retrieve a specific user's data from Firestore.
 * Requires authentication and only allows users to retrieve their own data.
 * @param {object} req - The Express request object, expecting `userId` in the URL parameters.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
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

/**
 * Handles PATCH requests to update a specific user's data in Firestore.
 * Requires authentication and only allows users to update their own data.
 * @param {object} req - The Express request object, expecting `userId` in the URL parameters and `name` or `email` in the body.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
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

/**
 * Handles DELETE requests to delete a specific user's data from Firestore.
 * Requires authentication and only allows users to delete their own account.
 * @param {object} req - The Express request object, expecting `userId` in the URL parameters.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.delete('/api/users/:userId', authenticate, async (req, res) => {
  try {
    const userId = req.params.userId;
    if (req.user.uid !== userId) {
      return res.status(403).json({ error: 'Forbidden: Cannot delete other user accounts' });
    }

    // 1. Delete seller card and products if user is a seller
    const sellerDoc = await db.collection('Sellers').doc(userId).get();
    if (sellerDoc.exists) {
      // Delete all products for this seller
      const productsRef = db.collection("Products");
      const q = productsRef.where("SellerID", "==", userId);
      const snapshot = await q.get();
      const batchDeletes = [];
      snapshot.forEach((docSnap) => {
        batchDeletes.push(db.collection("Products").doc(docSnap.id).delete());
      });
      await Promise.all(batchDeletes);

      // Delete the seller card
      await db.collection("Sellers").doc(userId).delete();
    }

    // 2. Delete user from Firestore
    await db.collection('Users').doc(userId).delete();

    // 3. Delete user from Firebase Authentication
    await admin.auth().deleteUser(userId);

    res.status(200).json({ message: 'User, seller card, and products deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user', details: error.message });
  }
});

// --- Utility/Admin Endpoints ---
/**
 * Handles GET requests to retrieve the count of users with a specific role.
 * Requires authentication.
 * @param {object} req - The Express request object, expecting `roleName` in the URL parameters.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
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

/**
 * Handles GET requests to retrieve the number of documents in a specific Firestore collection.
 * Requires authentication.
 * @param {object} req - The Express request object, expecting `collectionName` in the URL parameters.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
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

/**
 * Handles GET requests to retrieve the 5 latest sellers based on their `updatedAt` timestamp.
 * Requires authentication.
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.get('/api/seller/latest', authenticate, async (req, res) => {
  try {
    const sellersRef = db.collection('Sellers');

    const snapshot = await sellersRef
      .orderBy('updatedAt', 'desc')
      .limit(5)
      .get();

    if (snapshot.empty) {
      return res.status(200).json([]);
    }

    const latestSellers = [];
    snapshot.forEach(doc => {
      const sellerData = doc.data();
      console.log(sellerData.title)
      latestSellers.push({
        id: doc.id,
        name: sellerData.title,
      });
    });
    console.log(latestSellers.length)
    console.log(latestSellers)
    return res.status(200).json(latestSellers);

  } catch (error) {
    console.error('Error fetching latest sellers:', error);
    if (error.code === 'permission-denied') {
      return res.status(403).json({ message: 'Permission denied to access sellers data.' });
    }
    return res.status(500).json({ message: 'Internal server error while fetching latest sellers.' });
  }
});

/**
 * Handles GET requests to retrieve the top 5 sellers based on the number of orders they have.
 * Requires authentication.
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.get("/api/sellers/best", authenticate, async (req, res) => {
  try {
    const ordersRef = db.collection("Orders");
    const snapshot = await ordersRef.get();

    if (snapshot.empty) {
      return res.status(200).json([]);
    }

    const sellerCounts = {};

    snapshot.forEach(doc => {
      const orderData = doc.data();

      if (Array.isArray(orderData.items) && orderData.items.length > 0) {
        orderData.items.forEach(item => {
          if (item.Seller) {
            const sellerName = item.Seller;
            sellerCounts[sellerName] = (sellerCounts[sellerName] || 0) + 1;
          }
        });
      }
    });

    const sortedSellers = Object.keys(sellerCounts)
      .map(seller => ({ seller, count: sellerCounts[seller] }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const sellersWithId = await Promise.all(
      sortedSellers.map(async (sellerObj) => {
        const sellersRef = db.collection("Sellers");
        const sellerSnap = await sellersRef.where("title", "==", sellerObj.seller).limit(1).get();
        let id = null;
        if (!sellerSnap.empty) {
          id = sellerSnap.docs[0].id;
        }
        return {
          id,
          ...sellerObj
        };
      })
    );

    res.status(200).json(sellersWithId);
  } catch (error) {
    console.error("Error fetching top sellers:", error);
    res.status(500).json({ error: "Failed to fetch top sellers", details: error.message });
  }
});

/**
 * Handles GET requests to calculate and retrieve the total sales amount from all orders.
 * Requires authentication.
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.get('/api/sales/total', authenticate, async (req, res) => {
  try {
    const ordersRef = db.collection('Orders');
    const snapshot = await ordersRef.get();

    if (snapshot.empty) {
      return res.status(200).json({ totalSales: 0 });
    }

    let totalSales = 0;

    const parsePrice = (priceValue) => {
      if (typeof priceValue === 'string') {
        const numericString = priceValue.replace(/[^0-9.-]+/g, '').trim();
        return parseFloat(numericString) || 0;
      }
      return parseFloat(priceValue) || 0;
    };

    snapshot.forEach(doc => {
      const orderData = doc.data();
      let orderTotal = 0;

      if (Array.isArray(orderData.items)) {
        orderData.items.forEach(item => {
          const itemPrice = parsePrice(item.price);
          const itemQuantity = typeof item.quantity === 'number' ? item.quantity : 1;
          const itemSubtotal = itemPrice * itemQuantity;
          if (!isNaN(itemSubtotal)) {
            orderTotal += itemSubtotal;
          }
        });
      }

      totalSales += orderTotal;
    });

    res.status(200).json({ totalSales: parseFloat(totalSales.toFixed(2)) });
  } catch (error) {
    console.error('Error calculating overall sales:', error);
    res.status(500).json({ error: 'Failed to calculate overall sales', details: error.message });
  }
});

/**
 * Handles GET requests to retrieve the 5 latest orders.
 * Requires authentication.
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.get('/api/orders/latest', authenticate, async (req, res) => {
  try {
    const ordersRef = db.collection('Orders');
    const snapshot = await ordersRef.orderBy('createdAt', 'desc').limit(5).get();

    const parsePrice = (priceString) => {
      if (typeof priceString === 'string') {
        const numericString = priceString.replace('R', '').trim();
        return parseFloat(numericString) || 0;
      }
      return parseFloat(priceString) || 0;
    };

    const latestOrders = [];
    snapshot.forEach((doc) => {
      const data = doc.data();
      const total = Array.isArray(data.items)
        ? data.items.reduce((sum, item) => {
            const itemPrice = parsePrice(item.price);
            const itemQuantity = typeof item.quantity === 'number' ? item.quantity : 1;
            return sum + itemPrice * itemQuantity;
          }, 0).toFixed(2)
        : '0.00';

      latestOrders.push({
        id: doc.id,
        total,
      });
    });

    res.status(200).json({ latestOrders });
  } catch (error) {
    console.error("Error fetching latest orders:", error);
    res.status(500).json({ error: "Failed to fetch latest orders", details: error.message });
  }
});


/**
 * Helper function to parse price values from strings or numbers.
 * @param {string|number} priceValue - The price value to parse.
 * @returns {number} The parsed numeric price.
 */
const parsePrice = (priceValue) => {
  if (typeof priceValue === 'string') {
    const numericString = priceValue.replace(/[^0-9.-]+/g, '').trim();
    return parseFloat(numericString) || 0;
  }
  return parseFloat(priceValue) || 0;
};

/**
 * Handles GET requests to retrieve monthly sales performance data for the last 12 months.
 * Requires authentication.
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.get('/api/orders/monthly-performance', authenticate, async (req, res) => {
  try {
    const ordersRef = db.collection('Orders');

    const twelveMonthsAgo = new Date();
    twelveMonthsAgo.setFullYear(twelveMonthsAgo.getFullYear() - 1);
    twelveMonthsAgo.setDate(1);
    twelveMonthsAgo.setHours(0, 0, 0, 0);

    const querySnapshot = await ordersRef
      .where('createdAt', '>=', twelveMonthsAgo.toISOString())
      .orderBy('createdAt', 'asc')
      .get();

    const monthlySales = [];
    const now = new Date();
    for (let i = 0; i < 12; i++) {
      const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
      monthlySales.unshift({
        month: date.toLocaleString('en-US', { month: 'short' }),
        year: date.getFullYear(),
        total: 0,
      });
    }

    querySnapshot.forEach(doc => {
      const orderData = doc.data();
      const orderDate = new Date(orderData.createdAt);
      let orderTotal = 0;

      if (Array.isArray(orderData.items)) {
        orderData.items.forEach(item => {
          const itemPrice = parsePrice(item.price);
          const itemQuantity = typeof item.quantity === 'number' ? item.quantity : 1;
          const itemSubtotal = itemPrice * itemQuantity;
          if (!isNaN(itemSubtotal)) {
            orderTotal += itemSubtotal;
          }
        });
      }

      const targetMonthIndex = monthlySales.findIndex(m =>
        m.month === orderDate.toLocaleString('en-US', { month: 'short' }) &&
        m.year === orderDate.getFullYear()
      );

      if (targetMonthIndex !== -1) {
        monthlySales[targetMonthIndex].total += parseFloat(orderTotal.toFixed(2));
      }
    });

    res.status(200).json(monthlySales);

  } catch (error) {
    console.error('Error fetching monthly sales performance:', error);
    res.status(500).json({ error: 'Failed to fetch monthly sales performance', details: error.message });
  }
});

// --- Seller and Card Endpoints ---
/**
 * Handles DELETE requests to remove a seller card and all associated products.
 * Requires authentication and uses the authenticated user's ID to identify the seller.
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.delete('/api/seller/card', authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;

    // 1. Find all products for this seller
    const productsRef = db.collection("Products");
    const q = productsRef.where("SellerID", "==", userId);
    const snapshot = await q.get();

    // 2. Delete each product in a batch
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

/**
 * Handles POST requests to create or update a seller card.
 * If a seller card already exists for the authenticated user, it updates the existing one
 * and also updates the 'Seller' and 'genre' fields on all associated products.
 * If no seller card exists, it creates a new one using the user's ID as the document ID.
 * Requires authentication and expects seller card data in the request body.
 * @param {object} req - The Express request object, expecting `color`, `description`, `genre`, `image`, `textColor`, and `title` in the body.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
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
      image,
      textColor,
      title,
      userId: userId,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    const sellerCardRef = db.collection('Sellers').doc(userId);
    const docSnapshot = await sellerCardRef.get();

    if (docSnapshot.exists) {
      // Update existing card
      await sellerCardRef.update(sellerCardData);

      // Update all products with the new store name AND genre
      const productsRef = db.collection('Products');
      const productsSnap = await productsRef.where('SellerID', '==', userId).get();
      const batch = db.batch();
      productsSnap.forEach(doc => {
        batch.update(doc.ref, { Seller: title, genre: genre });
      });
      await batch.commit();

      res.status(200).json({ message: 'Seller card and products updated successfully.' });
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

/**
 * Handles POST requests to create a new seller with a Firestore-generated ID.
 * Requires authentication and expects seller data in the request body.
 * @param {object} req - The Express request object, expecting `color`, `description`, `genre`, `image`, `textColor`, and `title` in the body.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.post('/api/sellers', authenticate, async (req, res) => {
  try {
    const {
      color,
      description,
      genre,
      image,
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

/**
 * Handles GET requests to retrieve all seller documents from the 'Sellers' collection.
 * Does not require authentication, making seller data publicly accessible.
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
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

/**
 * Handles GET requests to retrieve the seller card data for the authenticated user.
 * Requires authentication. The user's UID is used to fetch their specific seller document.
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.get('/api/seller/card', authenticate, async (req, res) => {
  try {
    const userId = req.user.uid; // Get the authenticated user's ID
    const sellerDoc = await db.collection('Sellers').doc(userId).get(); // Fetch the seller document

    if (!sellerDoc.exists) {
      // If no seller card exists for this user ID, return a 404 not found error
      return res.status(404).json({ error: 'Seller card not found' });
    }

    // If the seller card exists, return its data
    res.status(200).json(sellerDoc.data());
  } catch (error) {
    console.error('Error fetching seller card:', error);
    res.status(500).json({ error: 'Failed to fetch seller card', details: error.message });
  }
});

//---Order Endpoints--
/**
 * Handles GET requests to retrieve a single order by its ID.
 * Requires authentication.
 * @param {object} req - The Express request object, expecting `orderId` in the URL parameters.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.get("/api/orders/:orderId", authenticate, async (req, res) => {
  try {
    const orderId = req.params.orderId;
    const orderDocRef = db.collection("Orders").doc(orderId);
    const orderSnap = await orderDocRef.get();

    if (!orderSnap.exists) {
      return res.status(404).json({ error: "Order not found" });
    }

    res.status(200).json({ id: orderSnap.id, ...orderSnap.data() });
  } catch (error) {
    console.error("Error retrieving order:", error);
    res.status(500).json({ error: "Failed to retrieve order", details: error.message });
  }
});

/**
 * Handles POST requests to place a new order.
 * It retrieves items from the user's cart, creates an order in the 'Orders' collection,
 * updates product sales and stock, and then clears the user's cart.
 * Requires authentication.
 * @param {object} req - The Express request object, expecting `orderDetails` (e.g., shipping info) in the body.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.post("/api/orders", authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;
    const orderDetails = req.body;

    // Retrieve cart items for the authenticated user
    const cartDocRef = db.collection("Carts").doc(userId);
    const cartDocSnap = await cartDocRef.get();
    const cartData = cartDocSnap.exists ? cartDocSnap.data() : null;
    const cartItems = cartData?.items || [];

    if (!cartItems.length) {
      return res.status(400).json({ error: "Cart is empty" });
    }

    // Prepare the order payload
    const orderPayload = {
      userId,
      items: cartItems,
      ...orderDetails, // Include any additional order details from the request body
      createdAt: new Date().toISOString(), // Use ISO string for consistent date storage
      status: "Pending", // Initial status of the order
    };

    // Create a new order document with an auto-generated ID
    const orderDocRef = db.collection("Orders").doc();
    await orderDocRef.set(orderPayload);

    // Update product sales and stock for each item in the order
    for (const item of cartItems) {
      if (item.id) {
        const productRef = db.collection("Products").doc(item.id);
        const productSnap = await productRef.get();
        if (productSnap.exists && productSnap.data().stock !== undefined) {
          await productRef.update({
            sales: admin.firestore.FieldValue.increment(1),
            stock: admin.firestore.FieldValue.increment(-1),
          });
        } else {
          // If stock is not defined, just increment sales
          await productRef.update({
            sales: admin.firestore.FieldValue.increment(1),
          });
        }
      }
    }

    // Clear the user's cart after the order is placed
    await cartDocRef.set({ items: [] }, { merge: true });

    res.status(200).json({ id: orderDocRef.id, ...orderPayload });
  } catch (error) {
    console.error("Error placing order:", error);
    res.status(500).json({ error: "Failed to place order", details: error.message });
  }
});

/**
 * Handles GET requests to retrieve all orders for the authenticated user.
 * Requires authentication.
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.get("/api/orders", authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;

    const ordersRef = db.collection("Orders");
    // Query orders where the 'userId' field matches the authenticated user's UID
    const q = ordersRef.where("userId", "==", userId);
    const snapshot = await q.get();

    const orders = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
    }));

    res.status(200).json(orders);
  } catch (error) {
    console.error("Error fetching user orders:", error);
    res.status(500).json({ error: "Failed to retrieve user orders", details: error.message });
  }
});

// --- Product Endpoints ---
/**
 * Handles POST requests to add a new product to the 'Products' collection.
 * It automatically associates the product with the authenticated user's seller card
 * to derive the seller's name and genre.
 * Requires authentication.
 * @param {object} req - The Express request object, expecting `image`, `name`, `price`, and `stock` in the body.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.post("/api/products", authenticate, async (req, res) => {
  try {
    const { image, name, price, stock } = req.body;
    const userId = req.user.uid;

    // Fetch seller card to get store name and genre
    const sellerDocRef = db.collection("Sellers").doc(userId);
    const sellerSnap = await sellerDocRef.get();

    let storeName = "Unknown Store";
    let storeGenre = "Unknown";

    if (sellerSnap.exists) {
      const sellerData = sellerSnap.data();
      storeName = sellerData.title || "Unknown Store";
      storeGenre = sellerData.genre || "Unknown";
    }

    // Add product to the 'Products' collection
    const productsRef = db.collection("Products");
    await productsRef.add({
      Seller: storeName, // Seller's store name
      SellerID: userId, // ID of the seller (user ID)
      image,
      name,
      price,
      stock,
      genre: storeGenre, // Genre of the seller's store
      createdAt: new Date(), // Timestamp for creation
    });

    res.status(200).json({ message: "Product added successfully." });
  } catch (error) {
    console.error("Error adding product:", error);
    res.status(500).json({ error: "Failed to add product", details: error.message });
  }
});

/**
 * Handles GET requests to retrieve all products associated with the authenticated seller (user).
 * Requires authentication.
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.get("/api/products/seller", authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;

    const productsRef = db.collection("Products");
    // Query products where 'SellerID' matches the authenticated user's UID
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

/**
 * Handles GET requests to retrieve a single product by its ID.
 * Does not require authentication, making product data publicly accessible.
 * @param {object} req - The Express request object, expecting `id` in the URL parameters.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.get("/api/products/:id", async (req, res) => {
  try {
    const productId = req.params.id;
    const productRef = db.collection("Products").doc(productId);
    const productSnap = await productRef.get();

    if (!productSnap.exists) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.status(200).json({ id: productSnap.id, ...productSnap.data() });
  } catch (error) {
    console.error("Error retrieving product:", error);
    res.status(500).json({ error: "Failed to retrieve product", details: error.message });
  }
});

/**
 * Handles PUT requests to update an existing product by its ID.
 * Requires authentication.
 * @param {object} req - The Express request object, expecting `id` in the URL parameters and `image`, `name`, `price`, `stock` in the body.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.put("/api/products/:id", authenticate, async (req, res) => {
  try {
    const productId = req.params.id;
    const { image, name, price, stock } = req.body; // Destructure updated fields

    const productRef = db.collection("Products").doc(productId);
    await productRef.update({
      image,
      name,
      price,
      stock,
      updatedAt: new Date(), // Timestamp for update
    });

    res.status(200).json({ message: "Product updated successfully." });
  } catch (error) {
    console.error("Error updating product:", error);
    res.status(500).json({ error: "Failed to update product", details: error.message });
  }
});

/**
 * Handles DELETE requests to remove a product by its ID.
 * Requires authentication.
 * @param {object} req - The Express request object, expecting `id` in the URL parameters.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.delete("/api/products/:id", authenticate, async (req, res) => {
  try {
    const productId = req.params.id;

    // Delete the document from the 'Products' collection
    await db.collection("Products").doc(productId).delete();

    res.status(200).json({ message: "Product deleted successfully." });
  } catch (error) {
    console.error("Error deleting product:", error);
    res.status(500).json({ error: "Failed to delete product", details: error.message });
  }
});

/**
 * Handles GET requests to retrieve products belonging to a specific seller.
 * Does not require authentication, making seller-specific product lists publicly accessible.
 * @param {object} req - The Express request object, expecting `sellerId` as a query parameter.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.get("/api/seller/products", async (req, res) => {
  const { sellerId } = req.query; // Get sellerId from query parameters
  if (!sellerId) {
    return res.status(400).json({ error: "Missing sellerId" });
  }

  try {
    const productsRef = db.collection("Products");
    // Query products where 'SellerID' matches the provided sellerId
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

/**
 * Handles GET requests to retrieve all products in the 'Products' collection.
 * Does not require authentication, making all product data publicly accessible.
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
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

/**
 * Handles PATCH requests to update the 'total' field of a specific product.
 * This route seems to be designed for incrementing/decrementing a product's 'total'
 * count or value (e.g., for analytics, likes, or a similar metric).
 * Requires authentication.
 * @param {object} req - The Express request object, expecting `id` in the URL parameters and `amount` (a number) in the body.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.patch("/api/products/:id/total", authenticate, async (req, res) => {
  try {
    const productId = req.params.id;
    const { amount } = req.body; // Amount to add to the total

    console.log("PATCH /api/products/:id/total", { productId, amount, type: typeof amount });

    // Validate that 'amount' is a number
    if (typeof amount !== "number" || isNaN(amount)) {
      return res.status(400).json({ error: "Amount must be a number." });
    }

    const productRef = db.collection("Products").doc(productId);
    const productSnap = await productRef.get();

    if (!productSnap.exists) {
      return res.status(404).json({ error: "Product not found" });
    }

    // Get current total, defaulting to 0 if not present
    const currentTotal = typeof productSnap.data().total === "number" ? productSnap.data().total : 0;
    const newTotal = currentTotal + amount; // Calculate the new total

    await productRef.update({
      total: newTotal, // Update the 'total' field
      updatedAt: new Date(), // Update the 'updatedAt' timestamp
    });

    res.status(200).json({ message: "Product total updated.", total: newTotal });
  } catch (error) {
    console.error("Error updating product total:", error);
    res.status(500).json({ error: "Failed to update product total", details: error.message });
  }
});



// --- Cart Endpoints ---
/**
 * Handles POST requests to add an item to the user's shopping cart.
 * If the cart exists, it checks if the item is already present; if not, it adds it.
 * If the cart doesn't exist, it creates a new cart with the item.
 * Requires authentication.
 * @param {object} req - The Express request object, expecting `id`, `name`, `price`, `imageUrl`, and `Seller` in the body.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.post("/api/cart/add", authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { id, name, price, imageUrl, Seller } = req.body;

    const cartRef = db.collection("Carts").doc(userId);
    const cartSnap = await cartRef.get();

    if (cartSnap.exists) {
      const cartData = cartSnap.data();
      // Check if the item is already in the cart to avoid duplicates
      const alreadyInCart = (cartData.items || []).some(item => item.id === id);

      if (!alreadyInCart) {
        // Use arrayUnion to atomically add the item to the 'items' array
        await cartRef.update({
          items: admin.firestore.FieldValue.arrayUnion({
            id,
            name,
            price,
            imageUrl,
            Seller,
            quantity: 1 // Initialize quantity to 1
          })
        });
      }
    } else {
      // If the cart doesn't exist, create it with the first item
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

/**
 * Handles POST requests to remove an item from the user's shopping cart.
 * Requires authentication.
 * @param {object} req - The Express request object, expecting `productId` in the body.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.post("/api/cart/remove", authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { productId } = req.body;

    const cartRef = db.collection("Carts").doc(userId);
    const cartSnap = await cartRef.get();

    if (cartSnap.exists) {
      const cartData = cartSnap.data();
      // Filter out the item to be removed
      const updatedItems = (cartData.items || []).filter(item => item.id !== productId);
      await cartRef.update({ items: updatedItems });

      res.status(200).json({ message: "Item removed", updatedItems });
    } else {
      // If cart doesn't exist, there's nothing to remove
      res.status(200).json({ message: "Cart not found, nothing to remove", updatedItems: [] });
    }
  } catch (error) {
    console.error("Error removing from cart:", error);
    res.status(500).json({ error: "Failed to remove from cart", details: error.message });
  }
});

/**
 * Handles GET requests to retrieve the contents of the user's shopping cart.
 * If the cart does not exist, it returns an empty array.
 * Requires authentication.
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object.
 * @returns {Promise<void>}
 */
app.get("/api/cart/retrieve", authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;
    const cartRef = db.collection("Carts").doc(userId);
    const cartSnap = await cartRef.get();

    if (cartSnap.exists) {
      const data = cartSnap.data();
      res.status(200).json({ items: data.items || [] }); // Return items, or an empty array if 'items' field is missing
    } else {
      // If cart document doesn't exist, return an empty array
      res.status(200).json({ items: [] });
    }
  } catch (error) {
    console.error("Error retrieving cart:", error);
    res.status(500).json({ error: "Failed to retrieve cart", details: error.message });
  }
});



// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend is running on port ${PORT}`);
});