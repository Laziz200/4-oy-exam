import express from 'express';
import ejsLayouts from 'express-ejs-layouts';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import Joi from 'joi';
import dotenv from 'dotenv';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, '..', 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
const BOOKMARKS_FILE = path.join(DATA_DIR, 'bookmarks.json');

const registerSchema = Joi.object({
  username: Joi.string().min(3).max(30).required().messages({
    'string.base': 'Foydalanuvchi nomi matn bo‘lishi kerak',
    'string.min': 'Foydalanuvchi nomi kamida 3 belgi bo‘lishi kerak',
    'string.max': 'Foydalanuvchi nomi 30 belgidan oshmasligi kerak',
    'any.required': 'Foydalanuvchi nomi kiritilishi shart'
  }),
  email: Joi.string().email().required().messages({
    'string.email': 'Yaroqli email manzilini kiriting',
    'any.required': 'Email kiritilishi shart'
  }),
  password: Joi.string().min(6).required().messages({
    'string.min': 'Parol kamida 6 belgi bo‘lishi kerak',
    'any.required': 'Parol kiritilishi shart'
  })
});

const loginSchema = Joi.object({
  email: Joi.string().email().required().messages({
    'string.email': 'Yaroqli email manzilini kiriting',
    'any.required': 'Email kiritilishi shart'
  }),
  password: Joi.string().required().messages({
    'any.required': 'Parol kiritilishi shart'
  })
});

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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(cookieParser());
app.set('view engine', 'ejs');
app.use(ejsLayouts);
app.set('layout', 'layout');

const defaultProducts = [
  { id: 1, name: 'Noutbuk', price: 999.99, stock: 10, image: '/assets/images/laptop.jpg' },
  { id: 2, name: 'Smartfon', price: 499.99, stock: 20, image: '/assets/images/Iphone.jpg' },
  { id: 3, name: 'Quloqchin', price: 79.99, stock: 50, image: '/assets/images/djoystik.jpg' },
  { id: 4, name: 'Playstation', price: 399.99, stock: 15, image: '/assets/images/playstation.jpg' },
  { id: 5, name: 'Televisor', price: 699.99, stock: 8, image: '/assets/images/televisor.jpg' }
];

const loadData = async () => {
  const users = await readJsonFile(USERS_FILE);
  const orders = await readJsonFile(ORDERS_FILE);
  const products = await readJsonFile(PRODUCTS_FILE, defaultProducts);
  const bookmarks = await readJsonFile(BOOKMARKS_FILE, {});
  return { users, orders, products, bookmarks };
};

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

app.get('/', authenticateToken, async (req, res) => {
  const { products, orders } = await loadData();
  const orderCount = orders.filter(o => o.username === req.user.username).length;
  res.render('index', { products, user: req.user, orderCount });
});

app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  const { error } = registerSchema.validate({ username, email, password });
  if (error) {
    return res.status(400).render('register', { error: error.details[0].message });
  }

  const { users } = await loadData();
  if (users.find(u => u.username === username)) {
    return res.status(400).render('register', { error: 'Foydalanuvchi nomi allaqachon mavjud' });
  }
  if (users.find(u => u.email === email)) {
    return res.status(400).render('register', { error: 'Email allaqachon ro‘yxatdan o‘tgan' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10); 
    const newUser = { username, email, password: hashedPassword };
    users.push(newUser);
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

  const { error } = loginSchema.validate({ email, password });
  if (error) {
    return res.status(400).render('login', { error: error.details[0].message });
  }

  const { users } = await loadData();
  const user = users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
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

app.get('/profile', authenticateToken, async (req, res) => {
  const { users } = await loadData();
  const user = users.find(u => u.username === req.user.username);
  if (!user) {
    return res.status(404).render('error', { message: 'Foydalanuvchi topilmadi. Iltimos, qayta kiring.' });
  }
  res.render('profile', { user, error: null });
});

app.post('/profile', authenticateToken, async (req, res) => {
  const { username, email } = req.body;
  if (!username || !email) {
    const { users } = await loadData();
    const user = users.find(u => u.username === req.user.username);
    if (!user) {
      return res.status(404).render('error', { message: 'Foydalanuvchi topilmadi.' });
    }
    return res.render('profile', { user, error: 'Foydalanuvchi nomi va email kiritilishi shart' });
  }
  const { users } = await loadData();
  const currentUser = users.find(u => u.username === req.user.username);
  if (!currentUser) {
    return res.status(404).render('error', { message: 'Foydalanuvchi topilmadi.' });
  }
  if (users.find(u => u.username === username && u.username !== currentUser.username)) {
    return res.render('profile', { user: currentUser, error: 'Foydalanuvchi nomi allaqachon mavjud' });
  }
  if (users.find(u => u.email === email && u.email !== currentUser.email)) {
    return res.render('profile', { user: currentUser, error: 'Email allaqachon ro‘yxatdan o‘tgan' });
  }
  currentUser.username = username;
  currentUser.email = email;
  try {
    await writeJsonFile(USERS_FILE, users);
    req.user.username = username; 
    res.redirect('/profile');
  } catch (err) {
    res.status(500).render('error', { message: 'Profile yangilashda xato yuz berdi' });
  }
});

app.post('/bookmark', authenticateToken, async (req, res) => {
  const { productId } = req.body;
  if (!productId) {
    return res.status(400).render('error', { message: 'Mahsulot ID si kiritilmadi' });
  }
  const { products, bookmarks } = await loadData();
  const product = products.find(p => p.id === parseInt(productId));
  if (!product) {
    return res.status(400).render('error', { message: 'Mahsulot topilmadi' });
  }
  const username = req.user.username;
  if (!bookmarks[username]) {
    bookmarks[username] = [];
  }
  if (!bookmarks[username].includes(productId)) {
    bookmarks[username].push(productId);
    await writeJsonFile(BOOKMARKS_FILE, bookmarks);
  }
  res.redirect('/');
});

app.get('/bookmarks', authenticateToken, async (req, res) => {
  const { products, bookmarks } = await loadData();
  const username = req.user.username;
  const bookmarkIds = bookmarks[username] || [];
  const bookmarkProducts = products.filter(p => bookmarkIds.includes(p.id));
  res.render('bookmarks', { products: bookmarkProducts, user: req.user });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  const statusCode = err.status || 500;
  const message = err.message || 'Serverda xatolik yuz berdi';
  res.status(statusCode).render('error', { message });
});

app.listen(PORT, async () => {
  await fs.mkdir(DATA_DIR, { recursive: true });
  console.log(`Server ${PORT}-portda ishlamoqda, soat ${new Date().toLocaleTimeString('uz-UZ', { timeZone: 'Asia/Tashkent' })}`);
});