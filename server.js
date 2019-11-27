require('dotenv').config()

const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');


app.use(express.json())

const posts = [{
    userName: 'chandu',
    title: 'post1'
}, {
    userName: 'sagar',
    title: 'post2'
}]

app.get('/posts', authenticateToken ,(req, res) => {
    const user = req.user;
    res.json(posts.filter(p => p.userName === user.name))
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        return res.sendStatus(401)
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next()
    })
}

app.listen(4000)