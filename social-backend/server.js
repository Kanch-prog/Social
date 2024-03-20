const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');
const secretKey = '123nkr';

const app = express();
const PORT = process.env.PORT || 5000;

// Session middleware
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: false,
}));

app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const storage = multer.diskStorage({
	destination: function (req, file, cb) {
		cb(null, 'uploads/');
	},
	filename: function (req, file, cb) {
		cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
	}
});

const upload = multer({ storage: storage });

mongoose.connect('mongodb://localhost:27017/Social', { useNewUrlParser: true, useUnifiedTopology: true });

const postSchema = new mongoose.Schema({
    title: String,
    content: String,
    file: String,
    likes: { type: Number, default: 0 },
    comments: [{ 
        text: String,
        user: { 
            type: mongoose.Schema.Types.ObjectId, 
            ref: 'User' // Reference to the user who made the comment
        } 
    }],
    user: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User' // Reference to the user who created the post
    }, 
    createdAt: { type: Date, default: Date.now } // Timestamp of when the post was created
});


const Post = mongoose.model('Post', postSchema);

// Define a user schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
});

// Create a User model
const User = mongoose.model('User', userSchema);

app.use(bodyParser.json());

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().populate('user', 'username').lean(); 
        for (const post of posts) {
            for (const comment of post.comments) {
                const user = await User.findById(comment.user);
                if (user) {
                    comment.user = { _id: user._id, username: user.username };
                }
            }
        }
        res.json(posts);
    } catch (error) {
        console.error('Error fetching posts:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route for user registration
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Check if the username already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        
        // Create a new user
        const newUser = new User({ username, password });
        await newUser.save();
        
        // Remove the password from the response for security reasons
        const userWithoutPassword = { ...newUser._doc };
        delete userWithoutPassword.password;
        
        res.status(201).json(userWithoutPassword);
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route for user login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username, password });
        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        
        // Create JWT token with user ID and username
        const token = jwt.sign({ userId: user._id, username: user.username }, secretKey);
        
        // Return the token and username in the response
        res.json({ token, username: user.username });
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Add middleware to extract user ID from the token
const extractUserId = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1]; // Extract token from headers
    if (token) {
        // Verify and decode the token to get user ID
        jwt.verify(token, secretKey, (err, decoded) => {
            if (err) {
                console.error('Error verifying token:', err);
                return res.status(401).json({ error: 'Unauthorized' });
            }
            req.userId = decoded.userId; // Attach userId to the request object
            next();
        });
    } else {
        return res.status(401).json({ error: 'Unauthorized' });
    }
};

// Apply the middleware to all routes
app.use((req, res, next) => {
    if (req.path === '/api/login' || req.path === '/api/register') {
        return next();
    }
    extractUserId(req, res, next);
});

app.post('/api/posts', upload.single('file'), async (req, res) => {
    try {
        const { title, content } = req.body;
        const file = req.file ? req.file.filename : undefined;
        const userId = req.userId; // Get userId from the request object

        if (!title || !content) {
            return res.status(400).json({ error: 'Title and content are required fields' });
        }

        const post = new Post({ title, content, file, user: userId });
        await post.save();
        res.status(201).json(post);
    } catch (error) {
        console.error('Error creating post:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/posts/like/:postId', extractUserId, async (req, res) => {
    try {
        const postId = req.params.postId;
        const post = await Post.findById(postId);

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        // Increment the likes count and save the post
        post.likes += 1;
        await post.save();

        res.json(post);
    } catch (error) {
        console.error('Error liking post:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/posts/comment/:postId', extractUserId, async (req, res) => {
    try {
        const postId = req.params.postId;
        const { text } = req.body;
        const userId = req.userId; 
        const post = await Post.findById(postId);

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        // Find the user who made the comment
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Add the comment with user information
        const comment = {
            text,
            user: { _id: user._id, username: user.username }
        };
        post.comments.push(comment);
        await post.save();

        // Populate user information for the newly added comment
        await post.populate('comments.user', 'username').execPopulate();

        res.json(post);
    } catch (error) {
        console.error('Error adding comment:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
});
