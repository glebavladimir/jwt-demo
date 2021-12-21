import env from 'dotenv';
import jwt from 'jsonwebtoken';

env.config();

export default function handler(request, reply) {
    if (request.method !== 'GET') {
        reply.status(405).send({ message: 'Only GET requests allowed' })
        return
    }

    const authHeader = request.headers['authorization'];
    const token = authHeader?.split(' ')[1];

    if (token === null) {
        reply.status(403).send({ message: "Auth token is required" })
        return
    }
    
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, user) => {
        if (error) {
            reply.status(403).send(error)
            return
        }
        console.log(user)
        reply.status(200).send({
            user: user
        });
    });
}
