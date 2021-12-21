import env from 'dotenv';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';

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
            w: "majority",
        }
    );
    console.info('[db] Mongoose is successfully connected')

    if (request.method === 'POST') {
        const token = request.body.token;
        if (token == null) {
            reply.status(400).send({ message: "Token is required" })
            return
        }
        const refreshToken = await RefreshToken.findOne({token: token}).exec()
        if (!refreshToken || !refreshToken.token) {
            reply.code(403).send({"error": "Invalid token"})
            return
        }

        jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (error, jwtUser) => {
            if (error) {
                reply.status(403).send(error)
                return
            }
            const accessToken = jwt.sign(
                { name: jwtUser.name }, 
                process.env.ACCESS_TOKEN_SECRET, 
                { expiresIn: '15s' }
            )
            reply.status(200).send({
                accessToken: accessToken
            });
        });
    } else if (request.method === 'DELETE') {
        const token = request.body.token;
        if (token === null) {
            reply.status(400).send({ message: "Token is required" })
            return
        }

        const refreshToken = await RefreshToken.findOneAndDelete({ token: token }).exec();
        if (!refreshToken || !refreshToken.token) {
            reply.status(403).send({"error": "Invalid token"})
            return
        }
        
        reply.status(204)
    } else {
        reply.status(405).send({ message: 'Only POST and DELETE requests allowed' })
        return
    }
}

export default handler
