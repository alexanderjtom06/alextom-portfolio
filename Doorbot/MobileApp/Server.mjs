import express from 'express';
import fs from 'node:fs/promises';
import url from 'node:url';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import 'dotenv/config';

const app = express();
const port = Secrets.env.PORT;
const secretKey = Secrets.env.JWT_SECRET;

app.use(express.json());

app.post('/login', async (req,res) => {
    const{username, password, role} = req.body;
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


    let token;
    if(acceptedUser.role === 'hardware'){
        token = jwt.sign(
            {userId: acceptedUser.username, role: acceptedUser.role}, 
            process.env.JWT_SECRET
        );
    } else{
        token = jwt.sign(
            {userId: acceptedUser.username, role: acceptedUser.role}, 
            process.env.JWT_SECRET, 
            {expiresIn: '10m'}
        );
    }

    return res.status(200).json({
        message: "Access granted!",
        token: token
    });
})

const wss = new WebSocketServer({noServer: true});
const activeConnections = new Map();

wss.on('connection', (ws, req) => {
    try{
        const parsedUrl = url.parse(req.url, true);
        const token = parsedUrl.query.token;

        if(!token){
            console.log("Missing token");
            ws.close(4001, "Authentication token missing");
            return;
        }

        const decodedPayload = jwt.verify(token, process.env.JWT_SECRET);
        const userRole = decodedPayload.role; 
        const currentUserId = decodedPayload.userId;
        activeConnections.set(userRole, ws);


        ws.on('message',(rawMessage) =>{
            const cleanMessage = JSON.parse(rawMessage);
            console.log(`Client recieved message ${cleanMessage}`);

            const ESP32 = activeConnections.get('hardware');

            if(cleanMessage.input === "UNLOCK"){
                const payload = {command: "UNLOCK" };
                ws.send(JSON.stringify(payload));
                if(ESP32){
                    ESP32.send(JSON.stringify(payload))
                }
            }
        });

    }
    catch{
        console.error("Invalid or expired token");
        ws.close(4002, "Authentication failed");
    }
});


app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
});

server.on('upgrade', (request, socket, head) =>{
    wss.handleUpgrade(request, socket, head, (wsSocket) =>{
        wss.emit('connection', wsSocket, request);
    });
});