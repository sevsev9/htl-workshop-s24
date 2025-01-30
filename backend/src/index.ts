import express from 'express';
import mongoose from 'mongoose';
import fs from "fs/promises";

import env from './util/env.util';
import router from './routes';
import logger from "./util/logger.util";
import cors from './util/cors.util';

const app = express();

app.use(express.json());

app.use(cors);

app.use("/api", router);

app.listen(env.PORT, async () => {
    logger.info('Server started.');

    const private_key = await fs.readFile(env.PRIVATE_KEY_FILE, 'utf-8');
    const public_key = await fs.readFile(env.PUBLIC_KEY_FILE, 'utf-8');

    process.env.PRIVATE_KEY = private_key;
    process.env.PUBLIC_KEY = public_key;

    logger.info('Keys loaded.');
    
    await mongoose.connect(env.MONGO_URL);

    logger.info('Connected to MongoDB.');
});
