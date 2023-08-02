const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const upload = multer({ dest: 'uploads/' });
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = 'saransh-key'; 


mongoose.connect('mongodb://localhost/document_management', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const documentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  type: { type: String, required: true },
  author: { type: String, required: true },
  validity: {
    start: { type: Date, required: true },
    end: { type: Date, required: true },
  },
  fileUrl: { type: String, required: true }, 
});

const Document = mongoose.model('Document', documentSchema);

function generateToken(user) {
  const payload = { username: user.username };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'An error occurred while registering the user.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const token = generateToken(user);
    res.status(200).json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'An error occurred while logging in.' });
  }
});

function authenticateToken(req, res, next) {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).json({ error: 'Access denied. Missing token.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token.' });
    }
    req.user = user;
    next();
  });
}

app.post('/api/documents', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    const { name, description, type, author, start, end } = req.body;
    

    if (!name || !type || !author || !start || !end || !req.file) {
      return res.status(400).json({ error: 'All mandatory fields must be provided.' });
    }

    const document = new Document({
      name,
      description,
      type,
      author,
      validity: { start: new Date(start), end: new Date(end) },
      fileUrl: req.file.path, 
    });

    await document.save();

    res.status(201).json({ message: 'Document saved successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'An error occurred while saving the document.' });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});