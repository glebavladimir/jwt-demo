import mongoose from 'mongoose';

const refreshTokenSchema = new mongoose.Schema({
    token: String
})

export default mongoose.model("RefreshToken", refreshTokenSchema)