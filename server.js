const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const PizZip = require('pizzip');
const Docxtemplater = require('docxtemplater');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
const port = 8000;

// Set up storage for multer
const upload = multer();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Generate a random session secret on server startup
const sessionSecret = crypto.randomBytes(64).toString('hex');

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 2 * 60 * 60 * 1000, // 2 hours
        sameSite: 'strict'
    }
}));

// Rate limiting for login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login attempts per windowMs
    message: { success: false, message: 'Too many login attempts, please try again later' }
});

// Simple admin credentials stored on the server (not visible to client)
const ADMIN_CREDENTIALS = {
    username: 'Hamdan',
    password: 'clockhamdan123'
};

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (req.session.authenticated) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
};

// Simplified login endpoint with plain text password comparison
app.post('/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    
    // Simple validation
    if (!username || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Username and password are required' 
        });
    }

    // Simple direct comparison
    if (username === ADMIN_CREDENTIALS.username && 
        password === ADMIN_CREDENTIALS.password) {
        
        // Set authenticated session
        req.session.authenticated = true;
        req.session.username = username;
        req.session.userAgent = req.headers['user-agent'];
        req.session.createdAt = Date.now();
        
        return res.json({ success: true });
    }
    
    // Invalid credentials
    res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// Add session verification
app.use((req, res, next) => {
    if (req.session.authenticated) {
        // Verify the user agent hasn't changed
        if (req.session.userAgent !== req.headers['user-agent']) {
            req.session.destroy();
            return res.status(401).json({ error: 'Session invalid' });
        }
    }
    next();
});

// Logout endpoint
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Logout failed' });
        }
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

// Check authentication status
app.get('/check-auth', (req, res) => {
    res.json({ authenticated: !!req.session.authenticated });
});

// Serve the form page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Protect the generate endpoint with authentication
app.post('/generate', requireAuth, upload.none(), async (req, res) => {
    try {
        const { rupees, senderName, senderAddress, productData, phoneNumber, date } = req.body;
        
        if (!rupees || !senderName || !senderAddress || !productData || !phoneNumber || !date) {
            return res.status(400).json({ 
                error: 'Missing required fields', 
                message: 'All fields are required' 
            });
        }
        
        const templatePath = path.join(__dirname, 'template.docx');
        const content = fs.readFileSync(templatePath, 'binary');
        const zip = new PizZip(content);
        const doc = new Docxtemplater(zip, {
            paragraphLoop: true,
            linebreaks: true
        });
        
        doc.setData({
            rupees: rupees,
            senderName: senderName,
            senderAddress: senderAddress,
            productData: productData,
            phoneNumber: phoneNumber,
            date: date
        });
        
        try {
            doc.render();
        } catch (error) {
            console.error('Error rendering document:', error);
            return res.status(500).json({
                error: 'Template Error',
                message: error.message
            });
        }
        
        const buffer = doc.getZip().generate({type: 'nodebuffer'});
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
        res.setHeader('Content-Disposition', 'attachment; filename=postal-order.docx');
        res.setHeader('Content-Length', buffer.length);
        res.send(buffer);
        
    } catch (error) {
        console.error('Error generating document:', error);
        res.status(500).json({ 
            error: 'Error generating document', 
            message: error.message 
        });
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});