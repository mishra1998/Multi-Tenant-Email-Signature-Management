require('dotenv').config();
const { Sequelize, DataTypes } = require('sequelize');
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const cors = require('cors');
const { Strategy } = require('passport-azure-ad-oauth2');
const axios = require('axios');
require('dotenv').config();
const path = require('path');
const { execFile } = require('child_process');

const app = express();
app.use(express.json());
app.use(cors());

const sequelize = new Sequelize(
    "email_signature",
    "********",
    "********",
    {
        host: process.env.DB_HOST,
        dialect: 'mysql',
        port: 3306,
        dialectOptions: {
            ssl: {
                require: true
            }
        },
        logging: false,
    }
);

sequelize.authenticate()
    .then(() => console.log('✅ PostgreSQL Connected'))
    .catch(err => console.error('❌ PostgreSQL Connection Error:', err));

const Template = sequelize.define('Template', {
    name: { type: DataTypes.STRING, allowNull: false },
    html: { type: DataTypes.TEXT, allowNull: false }
});

sequelize.sync();

passport.use(new Strategy({
    clientID: '9f6766f7-c9b6-46a0-a4c1-**********',
    clientSecret: 'gNe8Q~zVEjDwDBTRIFfdAz*********',
    callbackURL: 'https://agile-email-signature-dydmacbfh4e6cmf0.canadacentral-01.azurewebsites.net/auth/callback',
    tenant: 'common',
    authorizationURL: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenURL: 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
}, (accessToken, refreshToken, params, profile, done) => {
    done(null, { accessToken, refreshToken });
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

app.get('/auth/login', passport.authenticate('azure_ad_oauth2', {
    scope: ['https://graph.microsoft.com/.default']
}));

app.get('/auth/callback', passport.authenticate('azure_ad_oauth2', { failureRedirect: '/' }), (req, res) => {
    if (!req.user.accessToken) {
        return res.status(400).json({ error: "OAuth tokens missing" });
    }

    const token = req.user.accessToken;

    res.redirect(`http://localhost:5173/oauth/callback?access_token=${token}`);
});

app.get('/templates', async (req, res) => {
    try {
        const templates = await Template.findAll();
        res.json(templates);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/templates', async (req, res) => {
    try {
        const { name, html } = req.body;
        const newTemplate = await Template.create({ name, html });
        res.status(201).json(newTemplate);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/employees', async (req, res) => {
    try {
        let token = req.headers.authorization?.split(' ')[1] || req.session.token;
        if (!token) return res.status(401).json({ error: 'Unauthorized' });

        const response = await axios.get('https://graph.microsoft.com/v1.0/users', {
            headers: { Authorization: `Bearer ${token}` }
        });

        res.json(response.data.value);
    } catch (err) {
        console.error("Error fetching employees:", err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/apply-signature', (req, res) => {
    const { email, organization, html } = req.body;

    if (!email || !organization || !html) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    const sanitizedHtml = Buffer.from(html).toString('base64');

    const scriptPath = path.join(__dirname, 'applySignature.ps1');

    execFile('powershell.exe', [
        '-ExecutionPolicy', 'Bypass',
        '-File', scriptPath,
        '-email', email,
        '-organization', organization,
        '-sanitizedHtml', sanitizedHtml
    ], (error, stdout, stderr) => {
        if (error) {
            console.error(`Error: ${error.message}`);
            return res.status(500).json({ error: "Failed to execute script", details: stderr });
        }

        console.log(`PowerShell Output: ${stdout}`);
        res.json({ message: "Signature applied successfully", output: stdout });
    });
});

app.post('/apply-signature-to-all', async (req, res) => {
    try {
        const { organization, html } = req.body;
        let token = req.headers.authorization?.split(' ')[1] || req.session.token;

        if (!token || !organization || !html) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        const injectEmployeeData = (template, emp) => {
            return template
                .replace(/\$\{displayName\}/g, emp.displayName || "Employee Name")
                .replace(/\$\{givenName\}/g, emp.givenName || "Employee Given Name")
                .replace(/\$\{jobTitle\}/g, emp.jobTitle || "Employee Title")
                .replace(/\$\{mobilePhone\}/g, emp.mobilePhone || "+91 798225****")
                .replace(/\$\{mail\}/g, emp.mail || "email@example.com")
                .replace(/\$\{officeLocation\}/g, emp.officeLocation || "Employee Given Name");
        };

        const applySignature = (email, sanitizedHtml) => {
            return new Promise((resolve, reject) => {
                const scriptPath = path.join(__dirname, 'applySignature.ps1');

                execFile('powershell.exe', [
                    '-ExecutionPolicy', 'Bypass',
                    '-File', scriptPath,
                    '-email', email,
                    '-organization', organization,
                    '-sanitizedHtml', sanitizedHtml
                ], (error, stdout, stderr) => {
                    if (error) {
                        return reject({ email, error: error.message, stderr });
                    }
                    resolve({ email, output: stdout });
                });
            });
        };

        const response = await axios.get('https://graph.microsoft.com/v1.0/users', {
            headers: { Authorization: `Bearer ${token}` }
        });

        const users = response.data.value;
        const excludedEmail = 'rajesh.mishra@agileworldtechnologies.com';
        const results = [];

        for (const user of users) {
            const email = user.mail || user.userPrincipalName;

            if (!email || email.toLowerCase() === excludedEmail.toLowerCase()) {
                console.log(`Skipping signature for: ${email}`);
                continue;
            }

            const personalizedHtml = injectEmployeeData(html, user);
            const sanitizedHtml = Buffer.from(personalizedHtml).toString('base64');

            try {
                const result = await applySignature(email, sanitizedHtml);
                results.push(result);
            } catch (err) {
                results.push(err);
            }
        }

        res.json({
            message: "Signature applied to all users",
            results
        });

    } catch (err) {
        console.error("Error in /apply-signature-to-all:", err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/remove-signature', (req, res) => {
    const { email, organization } = req.body;

    if (!email || !organization) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    const scriptPath = path.join(__dirname, 'removeSignature.ps1');

    execFile('powershell.exe', [
        '-ExecutionPolicy', 'Bypass',
        '-File', scriptPath,
        '-email', email,
        '-organization', organization
    ], (error, stdout, stderr) => {
        if (error) {
            console.error(`Error: ${error.message}`);
            return res.status(500).json({ error: "Failed to execute script", details: stderr });
        }

        console.log(`PowerShell Output: ${stdout}`);
        res.json({ message: "Signature removal processed", output: stdout });
    });
});

app.post('/remove-signature-from-all', async (req, res) => {
    try {
        const { organization } = req.body;
        let token = req.headers.authorization?.split(' ')[1] || req.session.token;

        if (!token || !organization) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        const response = await axios.get('https://graph.microsoft.com/v1.0/users', {
            headers: { Authorization: `Bearer ${token}` }
        });

        const users = response.data.value;
        const excludedEmail = 'rajesh.mishra@agileworldtechnologies.com';
        const results = [];

        for (const user of users) {
            const email = user.mail || user.userPrincipalName;

            if (!email || email.toLowerCase() === excludedEmail.toLowerCase()) {
                console.log(`Skipping removal for: ${email}`);
                continue;
            }

            const scriptPath = path.join(__dirname, 'removeSignature.ps1');

            try {
                const result = await new Promise((resolve, reject) => {
                    execFile('powershell.exe', [
                        '-ExecutionPolicy', 'Bypass',
                        '-File', scriptPath,
                        '-email', email,
                        '-organization', organization
                    ], (error, stdout, stderr) => {
                        if (error) {
                            return reject({ email, error: error.message, stderr });
                        }
                        resolve({ email, output: stdout });
                    });
                });

                results.push(result);
            } catch (err) {
                results.push(err);
            }
        }

        res.json({
            message: "Signature removal attempted for all users",
            results
        });

    } catch (err) {
        console.error("Error in /remove-signature-from-all:", err);
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));