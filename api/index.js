import fastify from 'fastify';
import env from 'dotenv';
import jwt from 'jsonwebtoken';

env.config();

const app = fastify({logger: true});
const users = [{username: "admin", password: "admin"}];
let refreshTokens = [];

app.decorate('auth', authMiddleware).after(() => {
    app.route({
        method: 'GET', 
        url: '/', 
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
    
    if (!users.find((user) => user.username === username && user.password === password)) {
        reply.code(403).send({"error": "Authentication failed"});
    }

    const jwtUser = {
        name: username
    };
    const accessToken = generateAccessToken(jwtUser);
    const refreshToken = jwt.sign(jwtUser, process.env.REFRESH_TOKEN_SECRET);

    refreshTokens.push(refreshToken);
    
    reply.send({
        accessToken: accessToken,
        refreshToken: refreshToken
    });
});

app.post('/refresh', async (request, reply) => {
    const token = request.body.token;
    if (token == null) reply.code(400).send({"error": "Token is required"});
    if (!refreshTokens.find((existedToken) => existedToken === token)) reply.code(403).send({"error": "Invalid token"});

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

app.delete('/refresh_token', async (request, reply) => {
    const token = request.body.token;
    if (token == null) reply.code(400).send({"error": "Token is required"});
    if (!refreshTokens.find((existedToken) => existedToken === token)) reply.code(403).send({"error": "Invalid token"});

    refreshTokens = refreshTokens.filter((existedToken) => existedToken !== token);
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
    const token = authHeader && authHeader.split(' ')[1];

    return token;
}

app.listen(3000);