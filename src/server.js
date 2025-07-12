import express from 'express';
import ejsLayouts from 'express-ejs-layouts';
import jwt from 'jsonwebtoken';
import sha256 from 'sha256';
import dotenv from 'dotenv';
import fs from 'fs/promises';
import path from 'path';
import cookieParser from 'cookie-parser';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key';
const DATA_DIR = path.join(process.cwd(), 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');

// Ma'lumotlarni fayldan o'qish va yozish funksiyalari
const readJsonFile = async (filePath, defaultData = []) => {
  try {
    await fs.access(filePath);
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    await fs.mkdir(DATA_DIR, { recursive: true });
    await fs.writeFile(filePath, JSON.stringify(defaultData));
    return defaultData;
  }
};

const writeJsonFile = async (filePath, data) => {
  await fs.writeFile(filePath, JSON.stringify(data, null, 2));
};

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cookieParser()); // Cookie-parser middleware qo'shildi
app.set('view engine', 'ejs');
app.use(ejsLayouts);
app.set('layout', 'layout');

// Namuna mahsulotlar (agar fayl bo'sh bo'lsa)
const defaultProducts = [
  { id: 1, name: 'Noutbuk', price: 999.99, stock: 10 },
  { id: 2, name: 'Smartfon', price: 499.99, stock: 20 },
  { id: 3, name: 'Quloqchin', price: 79.99, stock: 50 }
];

// Ma'lumotlarni yuklash
const loadData = async () => {
  const users = await readJsonFile(USERS_FILE);
  const orders = await readJsonFile(ORDERS_FILE);
  const products = await readJsonFile(PRODUCTS_FILE, defaultProducts);
  return { users, orders, products };
};

// Autentifikatsiya middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token; // Tokenni cookie'dan o'qish
  if (!token) {
    return res.redirect('/login'); // Tizimga kirmagan bo'lsa, login sahifasiga
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).render('error', { message: 'Noto‘g‘ri token. Iltimos, qayta kiring.' });
    }
    req.user = user;
    next();
  });
};

// Marshrutlar
app.get('/', authenticateToken, async (req, res) => {
  const { products } = await loadData();
  res.render('index', { products });
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).render('error', { message: 'Foydalanuvchi nomi va parol kiritilishi shart' });
  }
  const { users } = await loadData();
  if (users.find(u => u.username === username)) {
    return res.status(400).render('error', { message: 'Foydalanuvchi nomi allaqachon mavjud' });
  }
  users.push({ username, password: sha256(password) });
  await writeJsonFile(USERS_FILE, users);
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).render('login', { error: 'Foydalanuvchi nomi va parol kiritilishi shart' });
  }
  const { users } = await loadData();
  const user = users.find(u => u.username === username && u.password === sha256(password));
  if (!user) {
    return res.status(401).render('login', { error: 'Noto‘g‘ri foydalanuvchi nomi yoki parol' });
  }
  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
  res.cookie('token', token, { httpOnly: true }); // Tokenni cookie sifatida saqlash
  res.redirect('/'); // Muvaffaqiyatli kirganda bosh sahifaga yo'naltirish
});

app.get('/dashboard', authenticateToken, async (req, res) => {
  const { orders } = await loadData();
  const userOrders = orders.filter(o => o.username === req.user.username);
  res.render('dashboard', { user: req.user, orders: userOrders });
});

app.post('/order', authenticateToken, async (req, res) => {
  const { productId, quantity } = req.body;
  if (!productId || !quantity || quantity <= 0) {
    return res.status(400).render('error', { message: 'Noto‘g‘ri mahsulot yoki miqdor' });
  }
  const { products, orders } = await loadData();
  const product = products.find(p => p.id === parseInt(productId));
  if (!product || product.stock < quantity) {
    return res.status(400).render('error', { message: 'Mahsulot mavjud emas yoki zaxira yetarli emas' });
  }
  product.stock -= quantity;
  orders.push({
    username: req.user.username,
    productId,
    productName: product.name,
    quantity: parseInt(quantity),
    totalPrice: product.price * quantity,
    date: new Date()
  });
  await writeJsonFile(PRODUCTS_FILE, products);
  await writeJsonFile(ORDERS_FILE, orders);
  res.redirect('/dashboard');
});

// Chiqish funksiyasi
app.get('/logout', (req, res) => {
  res.clearCookie('token'); // Tokenni cookie'dan o'chirish
  res.redirect('/login');
});

// Xatolarni boshqarish middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  const statusCode = err.status || 500;
  const message = err.message || 'Serverda xatolik yuz berdi';
  res.status(statusCode).render('error', { message });
});

// Serverni ishga tushirish
app.listen(PORT, async () => {
  await fs.mkdir(DATA_DIR, { recursive: true });
  console.log(`Server ${PORT}-portda ishlamoqda`);
});