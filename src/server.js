import express from 'express';
import ejsLayouts from 'express-ejs-layouts';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import Joi from 'joi';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import nodemailer from 'nodemailer';
import mongoose from 'mongoose'; 

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;
const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

mongoose.connect(process.env.dbUri)
  .then(() => console.log('MongoDB ga ulandi'))
  .catch(err => console.error('MongoDB ulanish xatosi:', err));

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, minlength: 3, maxlength: 30 },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, minlength: 6 },
});

const productSchema = new mongoose.Schema({
  id: { type: Number, required: true, unique: true },
  name: { type: String, required: true },
  price: { type: Number, required: true },
  stock: { type: Number, required: true },
  image: { type: String, required: true },
});

const orderSchema = new mongoose.Schema({
  username: { type: String, required: true },
  productId: { type: Number, required: true },
  productName: { type: String, required: true },
  quantity: { type: Number, required: true },
  totalPrice: { type: Number, required: true },
  date: { type: Date, default: Date.now },
});

const bookmarkSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  productIds: [{ type: Number }],
});

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);
const Bookmark = mongoose.model('Bookmark', bookmarkSchema);

const registerSchema = Joi.object({
  username: Joi.string().min(3).max(30).required().messages({
    'string.base': 'Foydalanuvchi nomi matn bo‘lishi kerak',
    'string.min': 'Foydalanuvchi nomi kamida 3 belgi bo‘lishi kerak',
    'string.max': 'Foydalanuvchi nomi 30 belgidan oshmasligi kerak',
    'any.required': 'Foydalanuvchi nomi kiritilishi shart',
  }),
  email: Joi.string().email().required().messages({
    'string.email': 'Yaroqli email manzilini kiriting',
    'any.required': 'Email kiritilishi shart',
  }),
  password: Joi.string().min(6).required().messages({
    'string.min': 'Parol kamida 6 belgi bo‘lishi kerak',
    'any.required': 'Parol kiritilishi shart',
  }),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required().messages({
    'string.email': 'Yaroqli email manzilini kiriting',
    'any.required': 'Email kiritilishi shart',
  }),
  password: Joi.string().required().messages({
    'any.required': 'Parol kiritilishi shart',
  }),
});

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
  { id: 5, name: 'Televisor', price: 699.99, stock: 8, image: '/assets/images/televisor.jpg' },
];

const initializeProducts = async () => {
  const productCount = await Product.countDocuments();
  if (productCount === 0) {
    await Product.insertMany(defaultProducts);
    console.log('Standart mahsulotlar MongoDB ga qo‘shildi');
  }
};

const loadData = async () => {
  await initializeProducts();
  const users = await User.find();
  const orders = await Order.find();
  const products = await Product.find();
  const bookmarks = await Bookmark.find();
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

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      if (existingUser.username === username) {
        return res.status(400).render('register', { error: 'Foydalanuvchi nomi allaqachon mavjud' });
      }
      if (existingUser.email === email) {
        return res.status(400).render('register', { error: 'Email allaqachon ro‘yxatdan o‘tgan' });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Ro‘yxatdan o‘tish muvaffaqiyatli!',
      html: `
        <h1>Xush kelibsiz, ${username}!</h1>
        <p>Sizning hisobingiz muvaffaqiyatli yaratildi.</p>
        <p>Email: ${email}</p>
        <p>Iltimos, hisobingizni faollashtirish uchun <a href="http://localhost:${PORT}/login">kirish</a> sahifasiga o‘ting.</p>
      `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Tasdiqlovchi email ${email} ga jo‘natildi`);

    res.redirect('/login');
  } catch (err) {
    console.error('Xato:', err);
    res.status(500).render('error', { message: 'Foydalanuvchi ma\'lumotlarini saqlash yoki email jo‘natishda xato yuz berdi' });
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

  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).render('login', { error: 'Noto‘g‘ri email yoki parol' });
    }
    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/');
  } catch (err) {
    console.error('Xato:', err);
    res.status(500).render('error', { message: 'Kirishda xato yuz berdi' });
  }
});

app.get('/dashboard', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).render('error', { message: 'Foydalanuvchi topilmadi. Iltimos, qayta kiring.' });
    }
    const orders = await Order.find({ username: req.user.username });
    const products = await Product.find(); 
    res.render('dashboard', { user, orders, products, success: null, error: null });
  } catch (err) {
    console.error('Xato:', err);
    res.status(500).render('error', { message: 'Dashboardni yuklashda xato yuz berdi' });
  }
});

app.post('/order', authenticateToken, async (req, res) => {
  const { productId, quantity } = req.body;
  if (!productId || !quantity || quantity <= 0) {
    return res.status(400).render('error', { message: 'Noto‘g‘ri mahsulot yoki miqdor' });
  }

  try {
    const product = await Product.findOne({ id: parseInt(productId) });
    if (!product || product.stock < quantity) {
      return res.status(400).render('error', { message: 'Mahsulot mavjud emas yoki zaxira yetarli emas' });
    }

    product.stock -= quantity;
    await product.save();

    const order = new Order({
      username: req.user.username,
      productId,
      productName: product.name,
      quantity: parseInt(quantity),
      totalPrice: product.price * quantity,
      date: new Date(),
    });
    await order.save();

    const user = await User.findOne({ username: req.user.username });
    if (user) {
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'Buyurtma tasdiqlandi!',
        html: `
          <h1>Hurmatli ${req.user.username},</h1>
          <p>Sizning buyurtmangiz muvaffaqiyatli qabul qilindi.</p>
          <p><strong>Mahsulot:</strong> ${product.name}</p>
          <p><strong>Miqdor:</strong> ${quantity}</p>
          <p><strong>Umumiy narx:</strong> $${(product.price * quantity).toFixed(2)}</p>
          <p><strong>Sana:</strong> ${new Date().toLocaleString('uz-UZ')}</p>
          <p>Batafsil ma'lumot uchun <a href="http://localhost:${PORT}/dashboard">dashboard</a> sahifasiga o‘ting.</p>
        `,
      };

      await transporter.sendMail(mailOptions);
      console.log(`Buyurtma tasdiqlovchi email ${user.email} ga jo‘natildi`);
    }

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Xato:', err);
    res.status(500).render('error', { message: 'Buyurtmani saqlash yoki email jo‘natishda xato yuz berdi' });
  }
});

app.post('/send-email', authenticateToken, async (req, res) => {
  const { message } = req.body;
  try {
    const user = await User.findOne({ username: req.user.username });
    const orders = await Order.find({ username: req.user.username });

    if (!message || !user) {
      return res.render('dashboard', { user, orders, error: 'Xabar yoki foydalanuvchi topilmadi', success: null });
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      subject: `Yangi xabar: ${req.user.username}`,
      html: `
        <h1>Yangi xabar</h1>
        <p><strong>Foydalanuvchi:</strong> ${req.user.username}</p>
        <p><strong>Email:</strong> ${user.email}</p>
        <p><strong>Xabar:</strong> ${message}</p>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.render('dashboard', { user, orders, success: 'Xabar muvaffaqiyatli jo‘natildi!', error: null });
  } catch (err) {
    console.error('Email jo‘natishda xato:', err);
    res.render('dashboard', { user, orders, error: 'Xabar jo‘natishda xato yuz berdi', success: null });
  }
});

app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).render('error', { message: 'Foydalanuvchi topilmadi. Iltimos, qayta kiring.' });
    }
    res.render('profile', { user, error: null });
  } catch (err) {
    console.error('Xato:', err);
    res.status(500).render('error', { message: 'Profilni yuklashda xato yuz berdi' });
  }
});

app.post('/profile', authenticateToken, async (req, res) => {
  const { username, email } = req.body;
  if (!username || !email) {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).render('error', { message: 'Foydalanuvchi topilmadi.' });
    }
    return res.render('profile', { user, error: 'Foydalanuvchi nomi va email kiritilishi shart' });
  }

  try {
    const currentUser = await User.findOne({ username: req.user.username });
    if (!currentUser) {
      return res.status(404).render('error', { message: 'Foydalanuvchi topilmadi.' });
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser && existingUser.username !== currentUser.username) {
      if (existingUser.username === username) {
        return res.render('profile', { user: currentUser, error: 'Foydalanuvchi nomi allaqachon mavjud' });
      }
      if (existingUser.email === email) {
        return res.render('profile', { user: currentUser, error: 'Email allaqachon ro‘yxatdan o‘tgan' });
      }
    }

    currentUser.username = username;
    currentUser.email = email;
    await currentUser.save();

    req.user.username = username;
    res.redirect('/profile');
  } catch (err) {
    console.error('Xato:', err);
    res.status(500).render('error', { message: 'Profile yangilashda xato yuz berdi' });
  }
});

app.post('/bookmark', authenticateToken, async (req, res) => {
  const { productId } = req.body;
  if (!productId) {
    return res.status(400).render('error', { message: 'Mahsulot ID si kiritilmadi' });
  }

  try {
    const product = await Product.findOne({ id: parseInt(productId) });
    if (!product) {
      return res.status(400).render('error', { message: 'Mahsulot topilmadi' });
    }

    let bookmark = await Bookmark.findOne({ username: req.user.username });
    if (!bookmark) {
      bookmark = new Bookmark({ username: req.user.username, productIds: [] });
    }

    if (!bookmark.productIds.includes(parseInt(productId))) {
      bookmark.productIds.push(parseInt(productId));
      await bookmark.save();
    }

    res.redirect('/');
  } catch (err) {
    console.error('Xato:', err);
    res.status(500).render('error', { message: 'Bookmark qo‘shishda xato yuz berdi' });
  }
});

app.get('/bookmarks', authenticateToken, async (req, res) => {
  try {
    const bookmark = await Bookmark.findOne({ username: req.user.username });
    const bookmarkIds = bookmark ? bookmark.productIds : [];
    const bookmarkProducts = await Product.find({ id: { $in: bookmarkIds } });
    res.render('bookmarks', { products: bookmarkProducts, user: req.user });
  } catch (err) {
    console.error('Xato:', err);
    res.status(500).render('error', { message: 'Bookmarklarni yuklashda xato yuz berdi' });
  }
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
  console.log(`Server ${PORT}-portda ishlamoqda, soat ${new Date().toLocaleTimeString('uz-UZ', { timeZone: 'Asia/Tashkent' })}`);
});