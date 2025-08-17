// server/index.js - Complete chat app backend with CRUD operations
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import http from "http";
import { Server } from "socket.io";
import multer from "multer";
import path from "path";
import fs from "fs";

// load environment variables from .env file
dotenv.config();

// create express app
const app = express();
// create http server for socket.io
const server = http.createServer(app);

// FIXED CORS CONFIGURATION - Allow multiple origins
const allowedOrigins = [
    "http://localhost:3000",
    "http://localhost:3001", 
    "https://omegachat-woad.vercel.app", // Replace with your actual Vercel URL
    // Add more domains as needed
];

// setup socket.io server for real-time chat with proper CORS
const io = new Server(server, {
    cors: {
        origin: allowedOrigins,
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true
    }
});

// setup middleware - these run before my routes
app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.log("CORS blocked origin:", origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(express.json()); // parse json data from requests

// create uploads folder if it doesn't exist
const uploadsDir = './uploads';
if (!fs.existsSync(uploadsDir)) {
  console.log("Creating uploads folder...");
  fs.mkdirSync(uploadsDir);
}

// setup file upload storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    console.log("Saving file to uploads folder");
    cb(null, './uploads/');
  },
  filename: function (req, file, cb) {
    // create unique filename: timestamp + original name
    const uniqueName = Date.now() + '-' + file.originalname;
    console.log("Saving file as:", uniqueName);
    cb(null, uniqueName);
  }
});

// file upload configuration
const upload = multer({ 
  storage: storage,
  limits: { 
    fileSize: 100 * 1024 * 1024 // 100MB limit
  },
  fileFilter: function (req, file, cb) {
    console.log("Checking file type:", file.mimetype);
    
    // allowed file types
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp',
      'video/mp4', 'video/avi', 'video/mov', 'video/wmv',
      'application/pdf', 'application/msword', 
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'text/plain'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
      console.log("File type allowed");
      cb(null, true);
    } else {
      console.log("File type not allowed:", file.mimetype);
      cb(new Error('Invalid file type! Only images, videos, and documents allowed.'), false);
    }
  }
});

// serve uploaded files statically
app.use('/uploads', express.static('uploads'));

// connect to mongodb database
console.log("Trying to connect to MongoDB...");
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log("✅ Successfully connected to MongoDB database!");
    })
    .catch((error) => {
        console.log("❌ Failed to connect to MongoDB:", error);
    });

// ===== DATABASE SCHEMAS =====

// schema for user data in database
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    mobile: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

// create indexes for faster database queries
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ mobile: 1 }, { unique: true });

// create User model from schema
const User = mongoose.model("User", userSchema);

// schema for chat messages - UPDATED with edit functionality
const messageSchema = new mongoose.Schema({
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    receiverId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    senderEmail: { type: String, required: true },
    receiverEmail: { type: String, required: true },
    message: { type: String }, // not required - can send just files
    fileUrl: { type: String }, // file path
    fileName: { type: String }, // original file name
    fileType: { type: String }, // image, video, or document
    fileSize: { type: Number }, // file size in bytes
    edited: { type: Boolean, default: false }, // NEW: track if message was edited
    editedAt: { type: Date }, // NEW: when it was edited
    timestamp: { type: Date, default: Date.now }
});

// create Message model from schema
const Message = mongoose.model("Message", messageSchema);

// ===== AUTHENTICATION MIDDLEWARE =====

// function to check if user has valid login token
const checkUserAuth = async (req, res, next) => {
    console.log("Checking if user is authenticated...");
    
    // get token from request headers
    const authHeader = req.headers["authorization"];
    const userToken = authHeader && authHeader.split(" ")[1];

    // if no token provided, user needs to login
    if (!userToken) {
        console.log("No token found - user needs to login");
        return res.status(401).json({ message: "Please login first" });
    }

    try {
        // verify the token is valid
        const decodedToken = jwt.verify(userToken, process.env.JWT_SECRET);
        console.log("Token is valid for user:", decodedToken.email);
        
        // find user in database
        const foundUser = await User.findById(decodedToken.id);
        if (!foundUser) {
            console.log("User not found in database");
            return res.status(401).json({ message: "User account not found" });
        }
        
        // add user info to request object
        req.user = foundUser;
        console.log("User authenticated successfully");
        next(); // continue to next function
        
    } catch (error) {
        console.log("Invalid token error:", error.message);
        return res.status(403).json({ message: "Invalid login token" });
    }
};

// ===== BASIC ROUTE FOR TESTING =====

// root route for testing
app.get("/", (req, res) => {
    res.json({ 
        message: "🚀 Omega Chat Backend is running!", 
        status: "active",
        endpoints: [
            "POST /api/signup - Create new account",
            "POST /api/login - User login",
            "GET /api/me - Get user profile",
            "GET /api/users - Get all users",
            "GET /api/messages/:email - Get messages",
            "POST /api/messages - Send message"
        ]
    });
});

// ===== USER REGISTRATION AND LOGIN ROUTES =====

// route for user signup/registration
app.post("/api/signup", async (req, res) => {
    console.log("New user trying to signup...");
    
    // get user data from request
    const { name, email, mobile, password } = req.body;
    console.log("Signup data received for:", email);

    try {
        // check if user already exists with same email or mobile
        const existingUser = await User.findOne({
            $or: [{ email: email }, { mobile: mobile }]
        });

        if (existingUser) {
            console.log("User already exists with this email/mobile");
            return res.status(400).json({
                message: "Account already exists with this email or mobile number"
            });
        }

        // hash the password for security
        console.log("Hashing password...");
        const hashedPassword = await bcrypt.hash(password, 12);

        // create new user object
        const newUser = new User({
            name: name,
            email: email,
            mobile: mobile,
            password: hashedPassword
        });

        // save user to database
        console.log("Saving new user to database...");
        await newUser.save();
        console.log("User saved successfully!");

        // create jwt token for automatic login after signup
        console.log("Creating login token for new user...");
        const loginToken = jwt.sign(
            { 
                id: newUser._id, 
                email: newUser.email 
            },
            process.env.JWT_SECRET,
            { expiresIn: "7d" } // token expires in 7 days
        );

        // send success response with token
        console.log("Signup successful for:", email);
        res.status(201).json({
            message: "Account created successfully!",
            token: loginToken,
            user: {
                id: newUser._id,
                name: newUser.name,
                email: newUser.email
            }
        });

    } catch (error) {
        console.log("Error during signup:", error);
        res.status(500).json({
            message: "Something went wrong during signup. Please try again."
        });
    }
});

// route for user login
app.post("/api/login", async (req, res) => {
    console.log("User trying to login...");
    
    // get login data from request
    const { email, password } = req.body;
    console.log("Login attempt for email:", email);

    try {
        // find user by email
        const foundUser = await User.findOne({ email: email });
        if (!foundUser) {
            console.log("No user found with this email");
            return res.status(400).json({
                message: "Wrong email or password"
            });
        }

        // check if password is correct
        console.log("Checking password...");
        const passwordIsCorrect = await bcrypt.compare(password, foundUser.password);
        if (!passwordIsCorrect) {
            console.log("Wrong password provided");
            return res.status(400).json({
                message: "Wrong email or password"
            });
        }

        // create jwt token for this login session
        console.log("Creating login token...");
        const loginToken = jwt.sign(
            { 
                id: foundUser._id, 
                email: foundUser.email 
            },
            process.env.JWT_SECRET,
            { expiresIn: "7d" } // token expires in 7 days
        );

        // send success response
        console.log("Login successful for:", email);
        res.json({
            token: loginToken,
            user: {
                id: foundUser._id,
                name: foundUser.name,
                email: foundUser.email
            },
            message: "Login successful!"
        });

    } catch (error) {
        console.log("Error during login:", error);
        res.status(500).json({
            message: "Something went wrong during login. Please try again."
        });
    }
});

// ===== EXISTING USER ROUTES =====

// route to get current user information
app.get("/api/me", checkUserAuth, (req, res) => {
    console.log("Getting current user info for:", req.user.email);
    
    // send user data (password not included for security)
    res.json({
        id: req.user._id,
        name: req.user.name,
        email: req.user.email,
        mobile: req.user.mobile
    });
});

// route to get all users except current user (for chat user list)
app.get("/api/users", checkUserAuth, async (req, res) => {
    console.log("Getting all users for chat list...");
    
    try {
        // find all users except current user, exclude password field
        const allUsers = await User.find(
            { _id: { $ne: req.user._id } }, // $ne means "not equal"
            { password: 0 } // exclude password field
        );
        
        console.log(`Found ${allUsers.length} other users`);
        res.json(allUsers);
        
    } catch (error) {
        console.log("Error getting users:", error);
        res.status(500).json({ message: "Could not load user list" });
    }
});

// ===== NEW CRUD ROUTES FOR USER MANAGEMENT =====

// UPDATE user profile (name and email)
app.put("/api/user/profile", checkUserAuth, async (req, res) => {
    console.log("User updating profile...");
    
    try {
        const { name, email } = req.body;
        console.log(`Updating profile for user: ${req.user.email}`);
        
        // check if new email is already taken by another user
        if (email !== req.user.email) {
            const existingUser = await User.findOne({ 
                email: email, 
                _id: { $ne: req.user._id } 
            });
            
            if (existingUser) {
                console.log("Email already in use by another user");
                return res.status(400).json({ message: "Email already in use" });
            }
        }

        // update user in database
        const updatedUser = await User.findByIdAndUpdate(
            req.user._id,
            { name: name, email: email },
            { new: true } // return updated user
        ).select('-password'); // don't return password

        console.log("✅ Profile updated successfully");
        res.json({ 
            message: "Profile updated successfully", 
            user: updatedUser 
        });
        
    } catch (error) {
        console.log("❌ Profile update error:", error);
        res.status(500).json({ message: "Error updating profile" });
    }
});

// UPDATE user password
app.put("/api/user/password", checkUserAuth, async (req, res) => {
    console.log("User changing password...");
    
    try {
        const { currentPassword, newPassword } = req.body;
        
        // find user in database
        const user = await User.findById(req.user._id);
        
        // check if current password is correct
        console.log("Verifying current password...");
        const isValidPassword = await bcrypt.compare(currentPassword, user.password);
        if (!isValidPassword) {
            console.log("Current password is incorrect");
            return res.status(400).json({ message: "Current password is incorrect" });
        }
        
        // hash new password
        console.log("Hashing new password...");
        const hashedNewPassword = await bcrypt.hash(newPassword, 12);
        
        // update password in database
        await User.findByIdAndUpdate(req.user._id, { password: hashedNewPassword });
        
        console.log("✅ Password changed successfully");
        res.json({ message: "Password changed successfully" });
        
    } catch (error) {
        console.log("❌ Password change error:", error);
        res.status(500).json({ message: "Error changing password" });
    }
});

// GET user statistics
app.get("/api/stats", checkUserAuth, async (req, res) => {
    console.log("Getting user statistics...");
    
    try {
        const userId = req.user._id;
        
        // count messages sent by user
        const messagesSent = await Message.countDocuments({ senderId: userId });
        
        // count messages received by user
        const messagesReceived = await Message.countDocuments({ receiverId: userId });
        
        // count total messages involving user
        const totalMessages = await Message.countDocuments({
            $or: [{ senderId: userId }, { receiverId: userId }]
        });
        
        // count files sent by user
        const filesSent = await Message.countDocuments({ 
            senderId: userId, 
            fileUrl: { $exists: true, $ne: null } 
        });
        
        // count total users in system
        const totalUsers = await User.countDocuments();
        
        const stats = {
            messagesSent: messagesSent,
            messagesReceived: messagesReceived,
            totalMessages: totalMessages,
            filesSent: filesSent,
            totalUsers: totalUsers - 1 // exclude current user
        };
        
        console.log("✅ Stats loaded successfully");
        res.json(stats);
        
    } catch (error) {
        console.log("❌ Stats loading error:", error);
        res.status(500).json({ message: "Error loading stats" });
    }
});

// DELETE user account
app.delete("/api/user/account", checkUserAuth, async (req, res) => {
    console.log("User trying to delete account...");
    
    try {
        const { password } = req.body;
        
        // find user in database
        const user = await User.findById(req.user._id);
        
        // verify password before deleting account
        console.log("Verifying password before account deletion...");
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            console.log("Password is incorrect");
            return res.status(400).json({ message: "Password is incorrect" });
        }
        
        // delete all messages sent or received by user
        console.log("Deleting user messages...");
        await Message.deleteMany({
            $or: [{ senderId: req.user._id }, { receiverId: req.user._id }]
        });
        
        // delete user account
        console.log("Deleting user account...");
        await User.findByIdAndDelete(req.user._id);
        
        console.log("✅ Account deleted successfully");
        res.json({ message: "Account deleted successfully" });
        
    } catch (error) {
        console.log("❌ Account deletion error:", error);
        res.status(500).json({ message: "Error deleting account" });
    }
});

// ===== FILE UPLOAD ROUTE =====

// route to handle file uploads
app.post('/api/upload', checkUserAuth, upload.single('file'), (req, res) => {
    console.log("File upload request received");
    
    try {
        if (!req.file) {
            console.log("No file received");
            return res.status(400).json({ message: 'No file uploaded' });
        }

        console.log("File uploaded successfully:", req.file.filename);
        
        // determine file type category
        let fileType = 'document';
        if (req.file.mimetype.startsWith('image/')) {
            fileType = 'image';
        } else if (req.file.mimetype.startsWith('video/')) {
            fileType = 'video';
        }

        // send file info back to frontend
        res.json({
            message: 'File uploaded successfully',
            fileUrl: `/uploads/${req.file.filename}`,
            fileName: req.file.originalname,
            fileType: fileType,
            fileSize: req.file.size
        });

    } catch (error) {
        console.error('File upload error:', error);
        res.status(500).json({ message: 'File upload failed' });
    }
});

// ===== MESSAGE ROUTES =====

// route to get messages between current user and another user
app.get("/api/messages/:receiverEmail", checkUserAuth, async (req, res) => {
    console.log("Getting messages...");
    
    try {
        // get receiver email from url parameter
        const { receiverEmail } = req.params;
        console.log(`Getting messages between ${req.user.email} and ${receiverEmail}`);
        
        // find the receiver user
        const receiverUser = await User.findOne({ email: receiverEmail });
        if (!receiverUser) {
            console.log("Receiver user not found");
            return res.status(404).json({ message: "User not found" });
        }

        // find all messages between these two users
        const chatMessages = await Message.find({
            $or: [
                // messages sent by current user to receiver
                { senderId: req.user._id, receiverId: receiverUser._id },
                // messages sent by receiver to current user
                { senderId: receiverUser._id, receiverId: req.user._id }
            ]
        }).sort({ timestamp: 1 }); // sort by time (oldest first)

        // format messages for frontend
        const formattedMessages = chatMessages.map(msg => ({
            _id: msg._id,
            senderId: msg.senderId,
            receiverId: msg.receiverId,
            sender: msg.senderEmail,
            receiver: msg.receiverEmail,
            senderEmail: msg.senderEmail,
            receiverEmail: msg.receiverEmail,
            message: msg.message,
            fileUrl: msg.fileUrl,
            fileName: msg.fileName,
            fileType: msg.fileType,
            fileSize: msg.fileSize,
            edited: msg.edited, // NEW
            editedAt: msg.editedAt, // NEW
            timestamp: msg.timestamp
        }));

        console.log(`Found ${formattedMessages.length} messages`);
        res.json(formattedMessages);
        
    } catch (error) {
        console.log("Error getting messages:", error);
        res.status(500).json({ message: "Could not load messages" });
    }
});

// route to send a new message
app.post("/api/messages", checkUserAuth, async (req, res) => {
    console.log("Sending new message...");
    
    try {
        // get message data from request
        const { receiver, receiverEmail, message, fileUrl, fileName, fileType, fileSize } = req.body;

        // handle both 'receiver' and 'receiverEmail' field names
        const targetUserEmail = receiverEmail || receiver;
        console.log(`Sending message from ${req.user.email} to ${targetUserEmail}`);

        if (!targetUserEmail) {
            console.log("No receiver email provided");
            return res.status(400).json({ message: "Receiver email is required" });
        }

        // check if we have either message text or file
        if (!message && !fileUrl) {
            console.log("No message text or file provided");
            return res.status(400).json({ message: "Message text or file required" });
        }

        // find the receiver user in database
        const receiverUser = await User.findOne({ email: targetUserEmail });
        if (!receiverUser) {
            console.log("Receiver user not found in database");
            return res.status(404).json({ message: "Receiver user not found" });
        }

        // create new message object
        const newMessage = new Message({
            senderId: req.user._id,
            senderEmail: req.user.email,
            receiverId: receiverUser._id,
            receiverEmail: receiverUser.email,
            message: message || '', // can be empty if only sending file
            fileUrl: fileUrl,
            fileName: fileName,
            fileType: fileType,
            fileSize: fileSize
        });

        // save message to database
        console.log("Saving message to database...");
        await newMessage.save();
        console.log("Message saved successfully!");

        // format message for frontend response
        const messageForFrontend = {
            _id: newMessage._id,
            senderId: newMessage.senderId,
            receiverId: newMessage.receiverId,
            sender: newMessage.senderEmail,
            receiver: newMessage.receiverEmail,
            senderEmail: newMessage.senderEmail,
            receiverEmail: newMessage.receiverEmail,
            message: newMessage.message,
            fileUrl: newMessage.fileUrl,
            fileName: newMessage.fileName,
            fileType: newMessage.fileType,
            fileSize: newMessage.fileSize,
            edited: newMessage.edited,
            editedAt: newMessage.editedAt,
            timestamp: newMessage.timestamp
        };

        // send real-time message to both users via socket.io
        console.log("Sending real-time message via socket.io...");
        io.to(receiverUser.email).emit("message", messageForFrontend);
        io.to(req.user.email).emit("message", messageForFrontend);

        // send success response
        res.status(201).json(messageForFrontend);
        
    } catch (error) {
        console.log("Error sending message:", error);
        res.status(500).json({ message: "Could not send message" });
    }
});

// ===== NEW CRUD ROUTES FOR MESSAGES =====

// UPDATE message (edit text messages only)
app.put("/api/message/:id", checkUserAuth, async (req, res) => {
    console.log("User editing message...");
    
    try {
        const { message: newText } = req.body;
        const messageId = req.params.id;
        
        // find message in database
        const foundMessage = await Message.findById(messageId);
        if (!foundMessage) {
            console.log("Message not found");
            return res.status(404).json({ message: "Message not found" });
        }
        
        // check if user owns this message
        if (foundMessage.senderId.toString() !== req.user._id.toString()) {
            console.log("User trying to edit someone else's message");
            return res.status(403).json({ message: "You can only edit your own messages" });
        }
        
        // don't allow editing messages with files
        if (foundMessage.fileUrl) {
            console.log("Cannot edit messages with files");
            return res.status(400).json({ message: "Cannot edit messages with files" });
        }
        
        // update message
        foundMessage.message = newText;
        foundMessage.edited = true;
        foundMessage.editedAt = new Date();
        await foundMessage.save();
        
        console.log("✅ Message edited successfully");
        
        // send real-time update to both users
        const updateData = {
            messageId: messageId,
            message: newText,
            edited: true,
            editedAt: foundMessage.editedAt
        };
        
        io.to(foundMessage.senderEmail).emit("messageEdited", updateData);
        io.to(foundMessage.receiverEmail).emit("messageEdited", updateData);
        
        res.json({ message: "Message edited successfully" });
        
    } catch (error) {
        console.log("❌ Message edit error:", error);
        res.status(500).json({ message: "Error editing message" });
    }
});

// DELETE message
app.delete("/api/message/:id", checkUserAuth, async (req, res) => {
    console.log("User deleting message...");
    
    try {
        const messageId = req.params.id;
        
        // find message in database
        const foundMessage = await Message.findById(messageId);
        if (!foundMessage) {
            console.log("Message not found");
            return res.status(404).json({ message: "Message not found" });
        }
        
        // check if user owns this message
        if (foundMessage.senderId.toString() !== req.user._id.toString()) {
            console.log("User trying to delete someone else's message");
            return res.status(403).json({ message: "You can only delete your own messages" });
        }
        
        // if message has a file, delete it from filesystem
        if (foundMessage.fileUrl) {
            const fileName = foundMessage.fileUrl.split('/').pop(); // get filename from URL
            const filePath = path.join('./uploads', fileName);
            
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
                console.log("🗑️ File deleted:", fileName);
            }
        }
        
        // delete message from database
        await Message.findByIdAndDelete(messageId);
        
        console.log("✅ Message deleted successfully");
        
        // send real-time update to both users
        io.to(foundMessage.senderEmail).emit("messageDeleted", { messageId: messageId });
        io.to(foundMessage.receiverEmail).emit("messageDeleted", { messageId: messageId });
        
        res.json({ message: "Message deleted successfully" });
        
    } catch (error) {
        console.log("❌ Message deletion error:", error);
        res.status(500).json({ message: "Error deleting message" });
    }
});

// SEARCH messages
app.get("/api/messages/search", checkUserAuth, async (req, res) => {
    console.log("User searching messages...");
    
    try {
        const { query } = req.query;
        const userId = req.user._id;
        
        if (!query) {
            console.log("No search query provided");
            return res.json([]);
        }
        
        // search for messages containing the query text
        const foundMessages = await Message.find({
            $and: [
                // only messages involving current user
                {
                    $or: [{ senderId: userId }, { receiverId: userId }]
                },
                // only messages containing search text
                {
                    message: { $regex: query, $options: 'i' } // case insensitive search
                }
            ]
        })
        .populate('senderId', 'name email')
        .populate('receiverId', 'name email')
        .sort({ timestamp: -1 }) // newest first
        .limit(50); // limit results
        
        console.log(`🔍 Found ${foundMessages.length} messages matching search`);
        res.json(foundMessages);
        
    } catch (error) {
        console.log("❌ Message search error:", error);
        res.status(500).json({ message: "Error searching messages" });
    }
});

// ===== SOCKET.IO REAL-TIME CHAT SETUP =====

// handle new socket.io connections
io.on("connection", (socket) => {
    console.log("New user connected to chat:", socket.id);

    // handle user authentication for socket connection
    const userToken = socket.handshake.auth.token;
    if (userToken) {
        try {
            // verify the token
            const decodedToken = jwt.verify(userToken, process.env.JWT_SECRET);
            socket.userEmail = decodedToken.email;
            
            // join user to their personal room (for receiving messages)
            socket.join(decodedToken.email);
            console.log(`${decodedToken.email} joined their chat room`);
            
        } catch (error) {
            console.log("Socket authentication error:", error);
            socket.disconnect();
        }
    }

    // handle manual room joining (backup method)
    socket.on("join", (userEmail) => {
        socket.join(userEmail);
        console.log(`${userEmail} manually joined their chat room`);
    });

    // handle user disconnection
    socket.on("disconnect", () => {
        console.log("User disconnected from chat:", socket.id);
    });
});

// ===== ERROR HANDLING =====

// Global error handler
app.use((error, req, res, next) => {
    console.log("Global error handler:", error.message);
    res.status(500).json({ 
        message: "Something went wrong on the server",
        error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
});

// Handle 404 routes
app.use('*', (req, res) => {
    res.status(404).json({
        message: "Route not found",
        availableRoutes: [
            "GET / - API status",
            "POST /api/signup - Create account", 
            "POST /api/login - User login",
            "GET /api/me - Get user profile",
            "GET /api/users - Get all users",
            "GET /api/messages/:email - Get messages",
            "POST /api/messages - Send message"
        ]
    });
});

// ===== START THE SERVER =====

// get port from environment or use default
const serverPort = process.env.PORT || 10000;

// start the server
server.listen(serverPort, () => {
    console.log(`🚀 Chat server is running on port ${serverPort}`);
    console.log(`📡 Socket.io server ready for real-time messaging`);
    console.log(`🔗 Backend URL: https://omega-chat-backend.onrender.com`);
    console.log(`📁 File uploads will be saved in ./uploads folder`);
    console.log(`✅ CORS configured for multiple origins`);
    console.log(`✅ CRUD operations ready:`);
    console.log(`   - CREATE: User signup ✅`);
    console.log(`   - READ: Get profile, messages, stats ✅`);
    console.log(`   - UPDATE: Edit profile, password, messages ✅`);
    console.log(`   - DELETE: Delete account, messages ✅`);
    console.log(`🎉 Your chat app is complete and ready!`);
});