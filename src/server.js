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
    console.log(`Fayl ${filePath} topilmadi, yangi fayl yaratilmoqda...`);
    await fs.mkdir(DATA_DIR, { recursive: true });
    await fs.writeFile(filePath, JSON.stringify(defaultData));
    return defaultData;
  }
};

const writeJsonFile = async (filePath, data) => {
  try {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
    console.log(`Ma'lumotlar ${filePath} ga muvaffaqiyatli yozildi`);
  } catch (err) {
    console.error(`Faylga yozishda xato: ${filePath}`, err);
    throw new Error('Malumotlarni faylga yozishda xato yuz berdi');
  }
};

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cookieParser());
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
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/login');
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
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).render('register', { error: 'Foydalanuvchi nomi, email va parol kiritilishi shart' });
  }
  const { users } = await loadData();
  if (users.find(u => u.username === username)) {
    return res.status(400).render('register', { error: 'Foydalanuvchi nomi allaqachon mavjud' });
  }
  if (users.find(u => u.email === email)) {
    return res.status(400).render('register', { error: 'Email allaqachon ro‘yxatdan o‘tgan' });
  }
  const newUser = { username, email, password: sha256(password) };
  users.push(newUser);
  try {
    await writeJsonFile(USERS_FILE, users);
    console.log(`Yangi foydalanuvchi qo'shildi: ${username}, ${email}`);
    res.redirect('/login');
  } catch (err) {
    res.status(500).render('error', { message: 'Foydalanuvchi ma\'lumotlarini saqlashda xato yuz berdi' });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).render('login', { error: 'Email va parol kiritilishi shart' });
  }
  const { users } = await loadData();
  const user = users.find(u => u.email === email && u.password === sha256(password));
  if (!user) {
    return res.status(401).render('login', { error: 'Noto‘g‘ri email yoki parol' });
  }
  const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
  res.cookie('token', token, { httpOnly: true });
  res.redirect('/');
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
  try {
    await writeJsonFile(PRODUCTS_FILE, products);
    await writeJsonFile(ORDERS_FILE, orders);
    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).render('error', { message: 'Buyurtmani saqlashda xato yuz berdi' });
  }
});

// Chiqish funksiyasi
app.get('/logout', (req, res) => {
  res.clearCookie('token');
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