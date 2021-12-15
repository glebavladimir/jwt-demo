import env from 'dotenv';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';

import User from '../model/User.js'
import RefreshToken from '../model/RefreshToken.js'

env.config();

async function handler(request, reply) {
    await mongoose.connect(
        process.env.DB_URI, 
        {
            dbName: process.env.DB_NAME,
            user: process.env.DB_USER,
            pass: process.env.DB_PASS,
            retryWrites: true,
            w: "majority"
        }
    );
    console.info('[db] Mongoose is successfully connected')

    if (request.method !== 'POST') {
        reply.status(405).send({ message: 'Only POST requests allowed' })
        return
    }
    const username = request.body.username
    if (username == null) {
        reply.status(400).send({ message: "Username is required" })
        return
    }
    const password = request.body.password
    if (password == null) {
        reply.status(400).send({ message: "Password is required" })
        return
    }
    const fetchedUser = await User.find({username: username, password: password}).exec()
    if (!fetchedUser.length) {
        reply.status(403).send({"error": "Authentication failed"})
        return
    }

    const jwtUser = {
        name: username
    }
    const accessToken = jwt.sign(jwtUser, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' })
    const refreshToken = jwt.sign(jwtUser, process.env.REFRESH_TOKEN_SECRET)

    await RefreshToken.create({token: refreshToken})
    
    reply.send({
        accessToken: accessToken,
        refreshToken: refreshToken
    })
}

export default handler
