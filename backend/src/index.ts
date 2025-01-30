import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';

import envUtil from './util/env.util';
import router from './routes';

const app = express();

app.use(express.json());

app.use(cors());

app.use("/", router);

const server = app.listen(envUtil.PORT, async () => {
    console.log('Server started.');
    
    await mongoose.connect(envUtil.MONGO_URL);

    console.log('Connected to MongoDB.');
});

process.once("SIGINT", closeServer);
process.once("SIGTERM", closeServer);

function closeServer(): Promise<void> {
    return new Promise(async (resolve) => {
        await mongoose.connection.close();
        server.close(err => {
            if (err) {
                console.log(err);
                resolve();
            } else {
                resolve();
            }
        });
    });
}
