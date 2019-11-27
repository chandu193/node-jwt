require('dotenv').config()

const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');


app.use(express.json())

/**
 * refresh token should be saved in a database or any other storage.
 * Else, whenever the server is restarted all the tokens that are in
 * the below array will be wiped out!!
 */
let refreshTokens = []

app.post('/login', (req, res) => {
    // authenticate user
    const userName = req.body.userName;
    const user = {
        name: userName
    }
    const accessToken = generateToken(user, '20s')
    const refreshToken = generateToken(user)
    refreshTokens.push(refreshToken)
    res.json({
        accessToken: accessToken,
        refreshToken: refreshToken
    });
})

app.post('/getToken', (req, res) => {
    const refreshToken = req.body.token;
    if(refreshToken == null){
      return res.sendStatus(401)
    }
    if(!refreshTokens.includes(refreshToken)){
      return res.sendStatus(403);
    }

    jwt.verify(refreshToken, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if(err){
            return res.sendStatus(403)
        }
        const accessToken = generateToken({name: user.name}, '20s')
        return res.json({accessToken: accessToken})
    })
})

app.delete('/logout', (req, res) => {
     refreshTokens = refreshTokens.filter(token => token !== req.body.token);
     res.sendStatus(204);
})

function generateToken(user, expiresIn = undefined){
    if(expiresIn){
        return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: expiresIn})
    }else{
        return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)
    }
}

app.listen(5000)