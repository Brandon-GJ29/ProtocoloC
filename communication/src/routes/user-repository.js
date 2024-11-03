import DBlocal from 'db-local';
import crypto from 'crypto';
import forge from 'node-forge';
import bcrypt from 'bcryptjs';
import fs from 'fs';

const { Schema } = new DBlocal({ path: './db' });

const User = Schema('User', {
    _id: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    publicKey: { type: String, required: true },
    encryptedPrivateKey: { type: String, required: true },
    salt: { type: String, required: true },
});

export class UserRepository {
    static async create({ username, password }) {
        if (typeof username !== 'string') throw new Error('Username debe ser un string');
        if (typeof password !== 'string') throw new Error('Password debe ser un string');

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            throw new Error('El usuario ya existe');
        }

        const id = crypto.randomUUID();
        const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair(2048);
        const publicKeyPem = forge.pki.publicKeyToPem(publicKey);
        const privateKeyPem = forge.pki.privateKeyToPem(privateKey);

        const salt = crypto.randomBytes(16).toString('hex'); // Crear un salt
        const hashedPassword = await bcrypt.hash(password, 10); // Hashear la contraseña

        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(hashedPassword.slice(0, 32)), Buffer.from(salt.slice(0, 16)));
        let encryptedPrivateKey = cipher.update(privateKeyPem, 'utf8', 'hex');
        encryptedPrivateKey += cipher.final('hex');

        const newUser = await User.create({
            _id: id,
            username,
            password: hashedPassword,
            publicKey: publicKeyPem,
            encryptedPrivateKey,
            salt
        }).save();

        // Generar el archivo PEM con la clave privada
        fs.writeFileSync(`./views/llaves/${username}_privateKey.pem`, privateKeyPem); // Cambia la ruta según sea necesario

        return { id, privateKeyPem };
    }

    static async login({ username, password }) {
        if (typeof username !== 'string') throw new Error('Username debe ser un string');
        if (typeof password !== 'string') throw new Error('Password debe ser un string');

        const user = await User.findOne({ username });

        if (user) {
            console.log('Usuario encontrado:', user);

            // Comparar la contraseña ingresada con el hash almacenado
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                console.log('Contraseña incorrecta');
                return null; // Contraseña incorrecta
            }

            // Continuar con el proceso si la contraseña es correcta
            if (!user.salt) {
                throw new Error('Salt no encontrado para el usuario');
            }

            // Desencriptar la clave privada
            const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(user.password.slice(0, 32)), Buffer.from(user.salt.slice(0, 16)));
            let privateKeyPem = decipher.update(user.encryptedPrivateKey, 'hex', 'utf8');
            privateKeyPem += decipher.final('utf8');

            console.log('Clave privada descifrada:', privateKeyPem);

            return user;
        } else {
            console.log('Usuario no encontrado');
            return null;
        }
    }

    // Nueva función para firmar un mensaje
    static signMessage(message, username) {
        const privateKey = fs.readFileSync(`./views/llaves/${username}_privateKey.pem`, 'utf8');
        const sign = crypto.createSign('SHA256');
        sign.update(message);
        sign.end();
        return sign.sign(privateKey, 'hex');
    }

    // Nueva función para verificar la firma
    static verifySignature(message, signature, publicKey) {
        const verify = crypto.createVerify('SHA256');
        verify.update(message);
        verify.end();
        return verify.verify(publicKey, signature, 'hex');
    }
}
