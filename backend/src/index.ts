import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';

import envUtil from './util/env.util';
import router from './routes';
import { BRAND } from 'zod';

const app = express();

app.use(express.json());

app.use(cors());

app.use("/api", router);

app.listen(envUtil.PORT, async () => {
    console.log('Server started.');
    
    await mongoose.connect(envUtil.MONGO_URL);

    console.log('Connected to MongoDB.');
});
