require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const session = require('express-session'); // More feature-rich than cookie-session

const app = express();

// Validate that session secret exists
if (!process.env.SESSION_SECRET) {
    console.error('ERROR: SESSION_SECRET environment variable is required!');
    process.exit(1);
}


app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        httpOnly: true, // Prevent XSS attacks
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax' // CSRF protection
    },
    name: 'roblox.sid' // Custom session cookie name
}));

// Environment variables (should be in .env file)
const ROBLOX_CLIENT_ID = '7419940331509569295';
const ROBLOX_CLIENT_SECRET = process.env.ROBLOX_CLIENT_SECRET; // Keep this secret!
const REDIRECT_URI = 'https://api.cipherinteractive.dev/oauth/callback';

// Generate state parameter
function generateState() {
    return crypto.randomBytes(16).toString('hex');
}

// 1. Initiate OAuth flow
app.get('/auth/roblox', (req, res) => {
    const state = generateState();
    req.session.oauthState = state;

    const authUrl = `https://apis.roblox.com/oauth/v1/authorize?${
        new URLSearchParams({
            client_id: ROBLOX_CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            response_type: 'code',
            scope: 'openid profile',
            state: state
        })
    }`;

    res.redirect(authUrl);
});

// 2. OAuth callback handler (matches your redirect_uri)
app.get('/oauth/callback', async (req, res) => {
    try {
        const { code, state, error, error_description } = req.query;

        // Handle OAuth errors
        if (error) {
            console.error('Roblox OAuth error:', error, error_description);
            return res.redirect('/login?error=roblox_oauth_failed&message=' + encodeURIComponent(error_description || error));
        }

        // Validate state parameter
        if (!state || state !== req.session.oauthState) {
            console.error('Invalid state parameter:', state, req.session.oauthState);
            return res.status(400).send('Invalid state parameter - possible CSRF attack');
        }

        // Exchange code for tokens
        const tokenResponse = await axios.post(
            'https://apis.roblox.com/oauth/v1/token',
            new URLSearchParams({
                client_id: ROBLOX_CLIENT_ID,
                client_secret: ROBLOX_CLIENT_SECRET,
                code: code,
                grant_type: 'authorization_code',
                redirect_uri: REDIRECT_URI
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                }
            }
        );

        const { access_token, refresh_token, expires_in, id_token, token_type } = tokenResponse.data;

        // Get user info from Roblox
        const userInfoResponse = await axios.get('https://apis.roblox.com/oauth/v1/userinfo', {
            headers: {
                'Authorization': `${token_type} ${access_token}`,
                'Accept': 'application/json'
            }
        });

        const userData = userInfoResponse.data;

        // Store user session
        req.session.robloxUser = {
            userId: userData.sub,
            username: userData.preferred_username,
            displayName: userData.name,
            profilePicture: userData.picture,
            accessToken: access_token,
            refreshToken: refresh_token,
            expiresAt: Date.now() + (expires_in * 1000)
        };

        // Clear the state
        delete req.session.oauthState;

        // Redirect to frontend or success page
        res.redirect(process.env.FRONTEND_URL + '/dashboard?success=true');

    } catch (error) {
        console.error('OAuth callback error:', error.response?.data || error.message);

        // Specific error handling
        if (error.response?.status === 400) {
            return res.redirect('/login?error=invalid_code');
        }
        if (error.response?.status === 401) {
            return res.redirect('/login?error=invalid_credentials');
        }

        res.redirect('/login?error=authentication_failed');
    }
});

// 3. Get current user profile
app.get('/api/user/profile', async (req, res) => {
    try {
        const { accessToken, userId } = req.session.robloxUser || {};

        if (!accessToken) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        // Get additional Roblox user data
        const [userInfo, robloxProfile] = await Promise.all([
            axios.get('https://apis.roblox.com/oauth/v1/userinfo', {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            }),
            axios.get(`https://users.roblox.com/v1/users/${userId}`, {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            })
        ]);

        res.json({
            oauthUser: userInfo.data,
            robloxProfile: robloxProfile.data,
            session: {
                expiresAt: req.session.robloxUser.expiresAt
            }
        });

    } catch (error) {
        console.error('Profile fetch error:', error.response?.data || error.message);
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
});

// 4. Logout endpoint
app.post('/auth/logout', (req, res) => {
    req.session = null;
    res.json({ success: true, message: 'Logged out successfully' });
});

// 5. Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        clientId: ROBLOX_CLIENT_ID,
        redirectUri: REDIRECT_URI
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`OAuth configured for client ID: ${ROBLOX_CLIENT_ID}`);
    console.log(`Callback URL: ${REDIRECT_URI}`);
});