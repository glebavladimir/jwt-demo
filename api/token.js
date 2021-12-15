import env from 'dotenv';
import jwt from 'jsonwebtoken';

env.config();

export default function handler(request, reply) {
    if (request.method === 'POST') {
        const token = request.body.token;
        if (token == null) {
            reply.status(400).send({ message: "Token is required" })
            return
        }
        // TODO: refactor to mongoDB
        // if (!refreshTokens.find((existedToken) => existedToken === token)) {
        //     reply.status(403).send({ message: "Invalid token" })
        //     return
        // }

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
        if (token == null) {
            reply.status(400).send({ message: "Token is required" })
            return
        }
        // TODO: refactor to mongoDB
        // if (!refreshTokens.find((existedToken) => existedToken === token)) {
        //     reply.status(403).send({ message: "Invalid token" })
        //     return
        // }

        // refreshTokens = refreshTokens.filter((existedToken) => existedToken !== token);
        reply.status(204)
    } else {
        reply.status(405).send({ message: 'Only POST requests allowed' })
        return
    }
}
