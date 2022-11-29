const express = require('express');
const { createUserTokenTable } = require('./dao/repository/userToken.repository');
const authRouter = require('./routes/authRouter')
const app = express();

app.use(express.json());
app.use('/auth', authRouter);


(() => {
    createUserTokenTable();
})();

app.listen(3000, (err) => {
    if(err) {
        console.log('Error in starting server', err);
    }
})