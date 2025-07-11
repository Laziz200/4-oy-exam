import express from 'express';
import ejsLayouts from 'express-ejs-layouts';
import jwt from 'jsonwebtoken';
import sha256 from 'sha256';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(ejsLayouts);
app.set('layout', 'layout'); // Layout faylini belgilash

// Namuna ma'lumotlar (xotirada saqlash uchun)
const users = [];
const products = [
  { id: 1, name: 'Noutbuk', price: 999.99, stock: 10 },
  { id: 2, name: 'Smartfon', price: 499.99, stock: 20 },
  { id: 3, name: 'Quloqchin', price: 79.99, stock: 50 }
];
const orders = [];

// Autentifikatsiya middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).render('error', { message: 'Kirish rad etildi' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).render('error', { message: 'Noto‘g‘ri token' });
    req.user = user;
    next();
  });
};

// Marshrutlar
app.get('/', (req, res) => {
  res.render('index', { products });
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (users.find(u => u.username === username)) {
    return res.status(400).render('error', { message: 'Foydalanuvchi nomi allaqachon mavjud' });
  }
  users.push({ username, password: sha256(password) });
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === sha256(password));
  if (!user) {
    return res.status(401).render('error', { message: 'Noto‘g‘ri ma’lumotlar' });
  }
  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
  res.setHeader('Authorization', `Bearer ${token}`);
  res.redirect('/dashboard');
});

app.get('/dashboard', authenticateToken, (req, res) => {
  const userOrders = orders.filter(o => o.username === req.user.username);
  res.render('dashboard', { user: req.user, orders: userOrders });
});

app.post('/order', authenticateToken, (req, res) => {
  const { productId, quantity } = req.body;
  const product = products.find(p => p.id === parseInt(productId));
  if (!product || product.stock < quantity) {
    return res.status(400).render('error', { message: 'Mahsulot mavjud emas yoki zaxira yetarli emas' });
  }
  product.stock -= quantity;
  orders.push({
    username: req.user.username,
    productId,
    productName: product.name,
    quantity,
    totalPrice: product.price * quantity,
    date: new Date()
  });
  res.redirect('/dashboard');
});

// Xatolarni boshqarish middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  const statusCode = err.status || 500;
  const message = err.message || 'Serverda xatolik yuz berdi';
  res.status(statusCode).render('error', { message });
});

// Serverni ishga tushirish
app.listen(PORT, () => {
  console.log(`Server ${PORT}-portda ishlamoqda`);
});