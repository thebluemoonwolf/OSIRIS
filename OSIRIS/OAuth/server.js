require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);

const app = express();

// Handle missing SESSION_SECRET
if (!process.env.SESSION_SECRET) {
    console.warn('⚠️  SESSION_SECRET not set, using temporary secret');
    process.env.SESSION_SECRET = crypto.randomBytes(64).toString('hex');
}

// Railway-specific configuration
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0'; // Required for Railway

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Enhanced session configuration for production
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    },
    store: new MemoryStore({
        checkPeriod: 86400000 // prune expired entries every 24h
    })
}));

// Trust proxy for Railway
app.set('trust proxy', 1);

// Debug middleware to catch route issues
app.use((req, res, next) => {
    console.log(`Incoming request: ${req.method} ${req.path}`);
    next();
});

// Health endpoint with environment info
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        environment: process.env.NODE_ENV,
        port: PORT,
        timestamp: new Date().toISOString(),
        hasSessionSecret: !!process.env.SESSION_SECRET,
        hasRobloxSecret: !!process.env.ROBLOX_CLIENT_SECRET
    });
});

// Debug endpoint to check environment
app.get('/api/debug/env', (req, res) => {
    res.json({
        node_env: process.env.NODE_ENV,
        port: process.env.PORT,
        railway_environment: process.env.RAILWAY_ENVIRONMENT,
        has_session_secret: !!process.env.SESSION_SECRET,
        has_roblox_secret: !!process.env.ROBLOX_CLIENT_SECRET,
        all_env_keys: Object.keys(process.env).filter(key =>
            key.includes('RAILWAY') ||
            key.includes('NODE') ||
            key === 'PORT'
        )
    });
});

// Generate state parameter
function generateState() {
    return crypto.randomBytes(16).toString('hex');
}

// Roblox OAuth initialization
app.get('/auth/roblox', (req, res) => {
    try {
        const state = generateState();
        req.session.oauthState = state;

        const authUrl = `https://apis.roblox.com/oauth/v1/authorize?${
            new URLSearchParams({
                client_id: process.env.ROBLOX_CLIENT_ID || '7419940331509569295',
                redirect_uri: process.env.RAILWAY_PUBLIC_DOMAIN ?
                    `https://${process.env.RAILWAY_PUBLIC_DOMAIN}/oauth/callback` :
                    process.env.REDIRECT_URI || 'https://your-project-name.up.railway.app/oauth/callback',
                response_type: 'code',
                scope: 'openid profile',
                state: state
            })
        }`;

        res.redirect(authUrl);
    } catch (error) {
        console.error('OAuth init error:', error);
        res.status(500).json({ error: 'Failed to initialize OAuth' });
    }
});

// OAuth callback handler
app.get('/oauth/callback', async (req, res) => {
    try {
        const { code, state, error, error_description } = req.query;

        if (error) {
            console.error('Roblox OAuth error:', error, error_description);
            return res.redirect('/login?error=roblox_oauth_failed');
        }

        if (!state || state !== req.session.oauthState) {
            return res.status(400).send('Invalid state parameter');
        }

        // Use environment variables with fallbacks
        const clientId = process.env.ROBLOX_CLIENT_ID || '7419940331509569295';
        const clientSecret = process.env.ROBLOX_CLIENT_SECRET;
        const redirectUri = process.env.RAILWAY_PUBLIC_DOMAIN ?
            `https://${process.env.RAILWAY_PUBLIC_DOMAIN}/oauth/callback` :
            process.env.REDIRECT_URI || 'https://your-project-name.up.railway.app/oauth/callback';

        if (!clientSecret) {
            throw new Error('ROBLOX_CLIENT_SECRET environment variable is required');
        }

        const tokenResponse = await axios.post(
            'https://apis.roblox.com/oauth/v1/token',
            new URLSearchParams({
                client_id: clientId,
                client_secret: clientSecret,
                code: code,
                grant_type: 'authorization_code',
                redirect_uri: redirectUri
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                }
            }
        );

        const { access_token, refresh_token, expires_in, id_token, token_type } = tokenResponse.data;

        // Get user info
        const userInfoResponse = await axios.get('https://apis.roblox.com/oauth/v1/userinfo', {
            headers: {
                'Authorization': `${token_type} ${access_token}`,
                'Accept': 'application/json'
            }
        });

        req.session.robloxUser = {
            userId: userInfoResponse.data.sub,
            username: userInfoResponse.data.preferred_username,
            displayName: userInfoResponse.data.name,
            accessToken: access_token,
            refreshToken: refresh_token,
            expiresAt: Date.now() + (expires_in * 1000)
        };

        delete req.session.oauthState;

        // Redirect to success page
        res.redirect(process.env.FRONTEND_URL || 'https://cipherinteractive.dev/dashboard');

    } catch (error) {
        console.error('OAuth callback error:', error.response?.data || error.message);
        res.redirect('/login?error=authentication_failed');
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Start server with Railway compatibility
app.listen(PORT, HOST, () => {
    console.log(`🚀 Server running on http://${HOST}:${PORT}`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔑 Session secret: ${process.env.SESSION_SECRET ? 'Set' : 'Generated'}`);
    console.log(`🎮 Roblox secret: ${process.env.ROBLOX_CLIENT_SECRET ? 'Set' : 'Missing'}`);
});

// Graceful shutdown for Railway
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    process.exit(0);
});
