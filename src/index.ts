import express from 'express';
import cors from 'cors';

import envUtil from './util/env.util';
import router from './routes';


const app = express();

app.use(express.json());

app.use(cors());

app.use("/", router)

app.listen(envUtil.PORT, () => {
    console.log('Server started.');
});
