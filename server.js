require('dotenv').config()

const express = require('express')
const app = express()
const User = require('./database/user_auth')
const bcrypt = require('bcrypt')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')

mongoose.connect(process.env.DATABASE_URL)
const db = mongoose.connection

app.use(express.json())

const bodyParser = require('body-parser')
app.use(bodyParser.json());

const cookieParser = require('cookie-parser')
app.use(cookieParser())

db.on('error', (error) => console.log(error))
db.once('open', () => console.log('Connected to database'))

//get all users
app.get('/users', authenticateToken, async (req, res) => {
    try {
        const username = req.username.user
        const users = await User.find({}, 'username');
        // const users = await User.find()

        const updatedAccessToken = await UpdateAccessToken(username);

        res.cookie('token', updatedAccessToken, { secure: true, sameSite: 'Strict', httpOnly: true });

        res.json({ 'users': users });
    }
    catch (error) {
        res.clearCookie('token')
        res.status(404).json({ message: 'Refresh token not found' });
    }
});

//home 
app.get('/', (req, res) => {
    res.status(200).json({
        message: 'Welcome to this API. Login to access the whole users data in /users'
    })
})

//singup
app.post('/signup', async (req, res) => {
    const username = req.body.username
    const password = req.body.password
    const user = await User.findOne({ username: username })

    if (!user) {
        try {
            const salt = await bcrypt.genSalt()
            const hashedPassword = await bcrypt.hash(password, salt)
            const user = new User({
                username: username,
                password: hashedPassword
            })

            const newUser = await user.save()
            res.json({ 'message': `new user ${username} added` })
        } catch (error) {
            res.status(500).json({ 'error': error.message })
        }
    } else {
        res.status(409).json({ message: "User already exists" })
    }
})

//login
app.post('/login', async (req, res) => {
    const username = req.body.username
    const password = req.body.password

    try {
        const user = await User.findOne({ username: username })
        if (!user) {
            return res.status(404).json({ message: "User not found" })
        }
        const passwordComparison = await bcrypt.compare(password, user.password)

        if (passwordComparison == true) {
            const accessToken = jwt.sign({ user: user.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' })
            const refreshToken = jwt.sign({ user: user.username }, process.env.ACCESS_TOKEN_SECRET)

            res.cookie("token", accessToken, { secure: true, sameSite: 'Strict', httpOnly: true })

            updatingRefreshToken = await User.updateOne({ username: user.username }, { $set: { refreshToken: refreshToken } })

            res.json({ 'message': 'Login Successful', user: user.username })
        }
        else {
            res.status(401).json({ message: 'Invaliid username or password' })
        }
    } catch (error) {
        res.status(400).json({ error: error.message })
    }
})

//logout
app.get('/logout', authenticateToken, async (req, res) => {
    try {
        const username = req.username.user

        await User.updateOne({ username: username }, { $set: { refreshToken: '' } })

        res.clearCookie('token')

        res.status(200).json({ message: "Successfully logged out" })
    } catch (error) {
        res.status(500).json({ message: error.message })
    }
})

//delete user
app.delete('/delete', async (req, res) => {
    try {
        const username = req.body.username
        const password = req.body.password
        const user = await User.findOne({ username: username })

        if (!user) {
            res.status(404).json({ message: 'Invalid username' })
        } else {
            const passwordComparison = await bcrypt.compare(password, user.password)

            if (passwordComparison == true) {
                await user.deleteOne({ username: username })
                res.send({ message: `${user.username} has successfully deleted` })
            } else {
                res.status(404).json({ message: 'Invalid username or password' })
            }
        }
    }
    catch (error) {
        res.status(500).json({ message: "internal server error", error: error })
    }
})

//update password
app.post('/update_password', authenticateToken, async (req, res) => {
    const username = req.username.user
    const password = req.body.password

    const updatedAccessToken = await UpdateAccessToken(username);
    res.cookie('token', updatedAccessToken, { secure: true, sameSite: 'Strict', httpOnly: true });

    const salt = await bcrypt.genSalt()
    const hashedPassword = await bcrypt.hash(password, salt)
    try {
        await User.updateOne({ username: username }, { $set: { password: hashedPassword } })
        res.json({ message: 'Successfully changed password' })
        res.status(204)
    }
    catch (error) {
        res.status(500).json({ message: 'Erron in changing password', error })
    }
})

//middlewares
function authenticateToken(req, res, next) {
    const token = req.cookies.token

    if (token == null) {
        return res.status(401).json({ message: 'Please Login' })
    }
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, username) => {
        if (error) {
            return res.status(403).json({ message: error.message })
        }
        req.username = username
        next()
    })
}

async function UpdateAccessToken(username) {
    try {
        const user = await User.findOne({ username: username });

        if (user.refreshToken) {
            const updatedAccessToken = jwt.sign({ user: user.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
            return updatedAccessToken;
        } else {
            UpdateAccessToken = 'refresh Token not found'
            throw error(UpdateAccessToken)
        }
    } catch (error) {
        console.error("Failed to update access token:", error.message);
        throw error;
    }
}

app.listen(3000, () => {
    console.log('server listening on port 3000')
})