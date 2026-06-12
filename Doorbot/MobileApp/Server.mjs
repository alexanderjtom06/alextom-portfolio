import express from 'express';
import fs from 'node:fs/promises';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();
const port = Secrets.env.PORT;
const secretKey = Secrets.env.JWT_SECRET;

app.use(express.json());

app.get('/', (req, res) => {
    console.log(`Connection received at: ${req.url}`);
    res.json({ message: "Hello from your new Express server!" });
});

app.post('/login', async (req,res) => {
    const{username, password} = req.body;
    const rawData = await fs.readFile('Users.json', 'utf8');
    const dataArray = JSON.parse(rawData);

    if(!username){
        return res.status(400).json({error: "Username Required"});
    }

    if(!password){
        return res.status(400).json({error: "Password Required"});
    }

    const acceptedUser = dataArray.find(user => user.username === username);
    console.log(`Attempting login for user: ${username}`);

    if(!acceptedUser){
        console.log(`Login failed: Username "${username}" not found.`);
        return res.status(401).json({error: "Invalid username or password"});
    }

    const isPasswordCorrect = await bcrypt.compare(password, acceptedUser.passwordHash);

    if(!isPasswordCorrect){
        console.log(`Login failed: Incorrect Password for "${username}".`);
        return res.status(401).json({error: "Invalid username or password"});
    }
    console.log(`Login successful for "${acceptedUser.username}"`);

    const token = jwt.sign(
        {userId: acceptedUser.username}, 
        process.env.JWT_SECRET, 
        {expiresIn: '10m'}
    );
    return res.status(200).json({
        message: "Access granted!",
        token: token
    });
})


app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
});