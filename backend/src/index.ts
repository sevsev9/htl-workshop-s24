import express from 'express';
import cors from './util/cors.util';
import mongoose from 'mongoose';

import envUtil from './util/env.util';
import router from './routes';
import logger from "./util/logger.util";

const app = express();

app.use(express.json());

app.use(cors);

app.use("/api", router);

app.listen(envUtil.PORT, async () => {
    logger.info('Server started.');
    
    await mongoose.connect(envUtil.MONGO_URL);

    logger.info('Connected to MongoDB.');
});
