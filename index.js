const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const flash = require('connect-flash');
const bcrypt = require('bcrypt');
const path = require('path');
const passport = require('passport');
const nodemailer = require('nodemailer');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const dotenv = require('dotenv');
const app = express();

dotenv.config();

// Define user schema and model
const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        unique: true,
        required: true
    },
    password: {
        type: String,
        required: function() {
            return !this.isOAuth; // password is required only if not OAuth user
        }
    },
    isOAuth: {
        type: Boolean,
        default: false
    },
    googleId: String,
    passwordResetToken: String,
    passwordResetExpires: Date
});

const User = mongoose.model('User', UserSchema);

// Connect to MongoDB
mongoose.connect('mongodb://0.0.0.0:27017/myapp', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// Configure app
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true
}));
app.use(flash());

app.use(passport.initialize());
app.use(passport.session());

// Passport serialize and deserialize user
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

// Google Strategy

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:4000/auth/google/callback'
},
(accessToken, refreshToken, profile, done) => {
    User.findOne({ googleId: profile.id }, (err, existingUser) => {
        if (err) return done(err);
        if (existingUser) {
            return done(null, existingUser);
        }
        // Create a new user if they don't exist
        const newUser = new User({
            name: profile.displayName,
            email: profile.emails[0].value,
            googleId: profile.id,
            isOAuth: true
        });
        newUser.save((err) => {
            if (err) return done(err);
            return done(null, newUser);
        });
    });
}));


// Routes
app.get('/', (req, res) => {
    const user = req.session.user;
    const message = req.flash('message')[0];
    res.render('index', { user, message });
});

app.get('/login', (req, res) => {
    const message = req.flash('message')[0];
    res.render('login', { message });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    User.findOne({ email }, (err, user) => {
        if (err) {
            req.flash('message', 'An error occurred');
            res.redirect('/login');
        } else if (!user) {
            req.flash('message', 'Email or password is incorrect');
            res.redirect('/login');
        } else {
            bcrypt.compare(password, user.password, (err, result) => {
                if (result) {
                    req.session.user = user;
                    res.render('index', { user, message: req.flash('message') });
                } else {
                    req.flash('message', 'Email or password is incorrect');
                    res.redirect('/login');
                }
            });
        }
    });
});

app.get('/reset-password', (req, res) => {
    const { token } = req.params;
    res.render('reset-password', { token, message: req.flash('message') });
});

app.post('/reset-password', (req, res) => {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;
    if (password !== confirmPassword) {
        req.flash('message', 'Passwords do not match');
        res.redirect(`/reset-password/${token}`);
        return;
    }
    User.findOneAndUpdate(
        { resetPasswordToken: token },
        { $set: { password: bcrypt.hashSync(password, 10), resetPasswordToken: null } },
        { new: true },
        (err, user) => {
            if (err) {
                req.flash('message', 'An error occurred while resetting your password');
                res.redirect(`/reset-password/${token}`);
            } else {
                req.flash('message', 'Your password has been reset successfully');
                res.redirect('/login');
            }
        }
    );
});

app.get('/forgot-password', (req, res) => {
    const message = req.flash('message')[0];
    res.render('forgot-password', { message });
});

app.post('/forgot-password', (req, res) => {
    const { email } = req.body;

    User.findOne({ email }, (err, user) => {
        if (err) {
            req.flash('message', 'An error occurred');
            return res.redirect('/forgot-password');
        }
        if (!user) {
            req.flash('message', 'No user with that email address found');
            return res.redirect('/forgot-password');
        }

        // Generate a reset token and expiration
        user.passwordResetToken = 'passwordnew';
        user.passwordResetExpires = Date.now() + 3600000; // 1 hour

        user.save(err => {
            if (err) {
                req.flash('message', 'An error occurred');
                return res.redirect('/forgot-password');
            }

            // Send password reset email
            const resetURL = `http://${req.headers.host}/reset-password/${user.passwordResetToken}`;

            const mailOptions = {
                to: user.email,
                from: 'your-email@example.com',
                subject: 'Password Reset',
                text: `You are receiving this because you (or someone else) have requested to reset the password for your account.\n\n
                Please click on the following link, or paste this into your browser, to complete the process:\n\n
                ${resetURL}\n\n
                If you did not request this, please ignore this email and your password will remain unchanged.`
            };

            transporter.sendMail(mailOptions, (err) => {
                if (err) {
                    req.flash('message', 'An error occurred while sending the email');
                    return res.redirect('/forgot-password');
                }
                req.flash('message', 'Password reset email sent');
                res.redirect('/forgot-password');
            });
        });
    });
});

app.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;

    User.findOne({
        passwordResetToken: token,
        passwordResetExpires: { $gt: Date.now() }
    }, (err, user) => {
        if (err || !user) {
            req.flash('message', 'Password reset token is invalid or has expired');
            return res.redirect('/forgot-password');
        }
        const message = req.flash('message')[0];
        res.render('reset-password', { token, message });
    });
});

app.post('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        req.flash('message', 'Passwords do not match');
        return res.redirect(`/reset-password/${token}`);
    }

    User.findOne({
        passwordResetToken: token,
        passwordResetExpires: { $gt: Date.now() }
    }, (err, user) => {
        if (err || !user) {
            req.flash('message', 'Password reset token is invalid or has expired');
            return res.redirect('/forgot-password');
        }

        user.password = bcrypt.hashSync(password, 10);
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;

        user.save(err => {
            if (err) {
                req.flash('message', 'An error occurred while resetting your password');
                return res.redirect(`/reset-password/${token}`);
            }

            req.flash('message', 'Your password has been reset successfully');
            res.redirect('/login');
        });
    });
});

app.get('/signup', (req, res) => {
    const message = req.flash('message')[0];
    res.render('signup', { message });
});

app.post('/signup', (req, res) => {
    const { name, email, password, confirmpassword } = req.body;

    // Check if passwords match
    if (password !== confirmpassword) {
        req.flash('message', 'Passwords do not match');
        return res.redirect('/signup');
    }

    User.findOne({ email }, (err, existingUser) => {
        if (err) {
            req.flash('message', 'An error occurred');
            console.log(err);
            return res.redirect('/signup');
        }
        if (existingUser) {
            req.flash('message', 'Email already exists');
            return res.redirect('/signup');
        }

        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                req.flash('message', 'An error occurred');
                console.log(err);
                return res.redirect('/signup');
            }

            const newUser = new User({
                name,
                email,
                password: hashedPassword
            });

            newUser.save()
                .then(() => {
                    req.session.user = newUser;
                    res.redirect('/');
                })
                .catch(err => {
                    if (err.code === 11000) {
                        req.flash('message', 'Email already exists');
                    } else {
                        req.flash('message', 'An error occurred');
                    }
                    res.redirect('/signup');
                });
        });
    });
});

app.get('/logout', (req, res) => {
    req.session.user = undefined;
    res.redirect('/');
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        req.session.user = req.user;
        res.redirect('/');
    }
);

app.post('/logout', (req, res) => {
    req.session.user = undefined;
    res.redirect('/');
});

// Start server
const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
