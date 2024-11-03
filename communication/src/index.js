import express from 'express';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import indexRoutes from './routes/index.js';
import { createServer } from 'node:http';
import { Server } from 'socket.io';
import { UserRepository } from './routes/user-repository.js';
import crypto from 'crypto';

const app = express();
const __dirname = dirname(fileURLToPath(import.meta.url));

app.set('views', join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(express.json());
app.use(express.static(join(__dirname, 'public')));
app.use(indexRoutes);
app.use('/views/llaves', express.static('views/llaves'));

const server = createServer(app);
const io = new Server(server);

const messages = [];
const connectedUsers = [];
const maxUsers = 2;

// Función para generar una clave simétrica
const generateSymmetricKey = () => crypto.randomBytes(32);

// Función para cifrar un mensaje usando AES
const encryptMessage = (message, symmetricKey) => {
    const iv = crypto.randomBytes(16); // Generar un vector de inicialización aleatorio
    const cipher = crypto.createCipheriv('aes-256-cbc', symmetricKey, iv); // Crear el cifrador AES
    let encryptedMessage = cipher.update(message, 'utf8', 'hex'); // Cifrar el mensaje
    encryptedMessage += cipher.final('hex'); // Finalizar el cifrado
    return { iv: iv.toString('hex'), encryptedMessage }; // Retornar IV y mensaje cifrado
};

// Función para descifrar un mensaje usando AES
const decryptMessage = (encryptedMessage, symmetricKey, iv) => {
    const decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, Buffer.from(iv, 'hex')); // Crear el descifrador AES
    let decryptedMessage = decipher.update(encryptedMessage, 'hex', 'utf8'); // Descifrar el mensaje
    decryptedMessage += decipher.final('utf8'); // Finalizar el descifrado
    return decryptedMessage; // Retornar el mensaje descifrado
};

// Función para hash SHA-256
const hashMessage = (message) => crypto.createHash('sha256').update(message).digest('hex'); // Generar un hash del mensaje

io.on('connection', (socket) => {
    console.log('A user has connected');
    socket.emit('chat initialized', messages.length === 0);

    socket.on('set username', (username) => {
        if (connectedUsers.length >= maxUsers) {
            socket.emit('chat full');
            socket.disconnect();
            return;
        }

        socket.username = username; // Almacenar el nombre de usuario
        connectedUsers.push(username);
        io.emit('user connected', connectedUsers);
        socket.emit('load previous messages', messages);
    });

    // Manejo del mensaje del usuario
    socket.on('chat message', async ({ msg, username }) => {
        try {
            const symmetricKey = generateSymmetricKey(); // Generar clave simétrica
            const { iv, encryptedMessage } = encryptMessage(msg, symmetricKey); // Cifrar mensaje
            const signature = UserRepository.signMessage(msg, username); // Firmar mensaje
            const messageHash = hashMessage(msg); // Generar hash para verificar integridad
            
            // Crear objeto de mensaje con datos relevantes
            const messageWithSignature = {
                msg: decryptMessage(encryptedMessage, symmetricKey, iv), // Mostrar el mensaje descifrado
                iv,
                signature,
                username,
                hash: messageHash // Hash del mensaje para integridad
            };

            messages.push(messageWithSignature); // Almacenar mensaje
            io.emit('chat message', messageWithSignature); // Emitir mensaje al chat
        } catch (error) {
            console.error('Error al procesar el mensaje:', error);
        }
    });

    socket.on('disconnect', () => {
        console.log('A user has disconnected');
        const index = connectedUsers.indexOf(socket.username);
        if (index > -1) {
            connectedUsers.splice(index, 1);
            io.emit('user connected', connectedUsers);
        }
    });
});

// Exportar el servidor y el objeto io
export { server, io };

const port = process.env.PORT || 8080;
server.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
