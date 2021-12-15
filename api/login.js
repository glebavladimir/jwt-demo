import env from 'dotenv';
import jwt from 'jsonwebtoken';

env.config();

const users = [{username: "admin", password: "admin"}];
let refreshTokens = [];

export default function handler(request, reply) {
    if (request.method !== 'POST') {
        reply.status(405).send({ message: 'Only POST requests allowed' })
        return
    }
    const username = request.body.username
    if (username == null) {
        reply.code(400).send({ message: "Username is required" })
        return
    }
    const password = request.body.password
    if (password == null) {
        reply.code(400).send({ message: "Password is required" })
        return
    }
    if (!users.find((user) => user.username === username && user.password === password)) {
        reply.status(403).send({ message: "Authentication failed" })
        return
    }

    const jwtUser = {
        name: username
    }
    const accessToken = jwt.sign(jwtUser, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' })
    const refreshToken = jwt.sign(jwtUser, process.env.REFRESH_TOKEN_SECRET)

    refreshTokens.push(refreshToken)
    
    reply.send({
        accessToken: accessToken,
        refreshToken: refreshToken
    })
}
