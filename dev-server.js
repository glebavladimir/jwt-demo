import fastify from 'fastify';
import env from 'dotenv';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';

env.config();

const app = fastify({logger: true});

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
import User from './model/User.js'
import RefreshToken from './model/RefreshToken.js'

app.decorate('auth', authMiddleware).after(() => {
    app.route({
        method: 'GET', 
        url: '/main', 
        preHandler: [app.auth], 
        handler: (request, reply) => {
            reply.send({
                "user": request.user
            });
        }
    });
});

app.post('/login', async (request, reply) => {
    const username = request.body.username;
    if (username == null) reply.code(400).send({"error": "Username is required"});
    const password = request.body.password;
    if (password == null) reply.code(400).send({"error": "Password is required"});
    
    const fetchedUser = await User.find({username: username, password: password}).exec()
    if (!fetchedUser.length) {
        reply.code(403).send({"error": "Authentication failed"});
    }

    const jwtUser = {
        name: username
    };
    const accessToken = generateAccessToken(jwtUser);
    const refreshToken = jwt.sign(jwtUser, process.env.REFRESH_TOKEN_SECRET);

    await RefreshToken.create({token: refreshToken})
    
    reply.send({
        accessToken: accessToken,
        refreshToken: refreshToken
    });
});

app.post('/token', async (request, reply) => {
    const token = request.body.token;
    if (token == null) reply.code(400).send({"error": "Token is required"});
    const refreshToken = await RefreshToken.findOne({token: token}).exec()
    if (!refreshToken || !refreshToken.token) reply.code(403).send({"error": "Invalid token"});

    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (error, jwtUser) => {
        if (error) reply.code(403).send(error);
        const accessToken = generateAccessToken({
            name: jwtUser.name
        });
        reply.send({
            accessToken: accessToken
        });
    });
});

app.delete('/token', async (request, reply) => {
    const token = request.body.token;
    const refreshToken = await RefreshToken.findOne({token: token}).exec()
    if (!refreshToken || !refreshToken.token) reply.code(403).send({"error": "Invalid token"});

    RefreshToken.findByIdAndRemove(refreshToken._id).exec();
    reply.code(204)
});

function generateAccessToken(jwtUser) {
    return jwt.sign(jwtUser, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' });
}

function authMiddleware(request, reply, done) {
    const token = getAuthToken(request);
    if (token == null) reply.code(403).send();
    
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, user) => {
        if (error) reply.code(403).send(error);
        request.user = user;
    });
    done();
}

function getAuthToken(request) {
    const authHeader = request.headers['authorization'];
    const token = authHeader?.split(' ')[1];

    return token;
}

app.listen(3000);
