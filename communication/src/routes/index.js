import express, { Router } from 'express';
import { UserRepository } from './user-repository.js';
import logger from 'morgan';
import { io } from '../index.js'; // Importa io desde el archivo principal
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer'; // Importar multer

// Obtener la ruta del directorio actual
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuración de multer para guardar archivos en views/llaves/
const storage = multer.diskStorage({
    destination: path.join(__dirname, '../views/llaves'),
    filename: (req, file, cb) => {
        cb(null, `${file.originalname}`); // Nombre único para el archivo
    }
});

const upload = multer({ storage });

const router = Router();

router.use(express.json());
router.use(logger('dev'));

// Ruta principal
router.get('/', (req, res) => res.render('index', { title: 'Protocolo de comunicación' }));

// Ruta para iniciar sesión
router.get('/signin', (req, res) => res.render('signin', { title: 'Login' }));

// Ruta para registro de usuarios
router.get('/signup', (req, res) => res.render('signup', { title: 'Registro' }));

router.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    console.log(req.body);

    try {
        const { id, privateKeyPem } = await UserRepository.create({ username, password });
        res.status(200).send({ message: 'Registro exitoso', fileName: `${username}_privateKey.pem` });
    } catch (error) {
        res.status(400).send(error.message);
    }
});

// Ruta para eliminar llaves
router.delete('/deleteKey/:filename', (req, res) => {
    const fileName = req.params.filename;
    const filePath = path.join(__dirname, '../views/llaves', fileName);

    fs.unlink(filePath, (err) => {
        if (err) {
            console.error('Error al eliminar la llave:', err);
            return res.status(500).send({ message: 'Error al eliminar la llave' });
        }
        res.status(200).send({ message: 'Llave eliminada' });
    });
});

// Ruta de inicio de sesión con carga de archivo
router.post('/signin', upload.single('file'), async (req, res) => {
    console.log('Solicitud recibida en /signin', req.body);
    const { username, password } = req.body;

    try {
        // Llamar a UserRepository.login con username y password
        const user = await UserRepository.login({ username, password });
        if (user) {
            console.log('Usuario autenticado:', user);
            if (req.file) {
                console.log('Archivo guardado en:', req.file.path);
                res.status(200).send({ message: 'Inicio de sesión exitoso', user });
            } else {
                res.status(200).send({ message: 'Usuario encontrado, pero no se subió ningún archivo', user });
            }
        } else {
            res.status(401).send({ message: 'Credenciales incorrectas' });
        }
    } catch (error) {
        console.error('Error en la solicitud:', error);
        res.status(500).send({ message: 'Error en el inicio de sesión', error: error.message });
    }
});

// Rutas para el chat
router.get('/chat', (req, res) => res.render('chat', { title: 'Chat' }));

router.get('/select', (req, res) => res.render('select', { title: 'Seleccion' }));

export default router;
