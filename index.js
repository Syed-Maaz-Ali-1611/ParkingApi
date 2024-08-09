const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')('sk_test_51PNdjnECRSK15cD8HRmCflGJ9mUSD2dRjmarD51EiG53pYFMgHkQqi6s19U7E7Ly1eZsk58U2Me6ppTTtxm1UwqH001VP8W7tU');
const app = express();
const SECRET_KEY = 'd84814d82fc09705be3959d857fd5f78b67a6a997c4b3f6b46f5b23c6f313333677e40df4da1293276873126a44d4788ef6b9baebf6d3b998d5cd7c43f2fad00';

app.use(bodyParser.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

mongoose.connect('mongodb+srv://parking:parking123@parking.lfdltcn.mongodb.net/test?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
  insertSampleSlots();
});

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  age: { type: Number },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  vehicle: { type: String },
  model: { type: String },
  licensePlate: { type: String },
  owner: { type: String },
  profilePic: { type: String },
});

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

const User = mongoose.model('User', UserSchema);

const ReservationSchema = new mongoose.Schema({
  userEmail: { type: String, required: true },
  vehicleName: { type: String, required: true },
  vehicleType: { type: String, required: true },
  parkingLocation: { type: String, required: true },
  selectedSlots: [{ id: String, selected: Boolean, unavailable: Boolean }],
  date: { type: Date, required: true },
  startTime: { type: Date, required: true },
  endTime: { type: Date, required: true },
  totalCharges: { type: Number, required: true }
});

const Reservation = mongoose.model('Reservation', ReservationSchema);

const SlotSchema = new mongoose.Schema({
  parkingLocation: { type: String, required: true },
  slots: [{ id: String, selected: Boolean, unavailable: Boolean }]
});

const Slot = mongoose.model('Slot', SlotSchema);

const transporter = nodemailer.createTransport({
  service: 'hotmail',
  auth: {
    user: 'weppso@outlook.com',
    pass: 'Software123+',
  },
});

const isPasswordValid = (password) => {
  const minLength = 8;
  const alphanumeric = /^[a-zA-Z0-9]*$/;
  return password.length >= minLength && alphanumeric.test(password);
};

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.join(__dirname, 'uploads');
    console.log('Upload Path:', uploadPath); // Log the upload path
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});



const upload = multer({ storage: storage });

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!isPasswordValid(password)) {
    return res.status(400).json({ message: 'Password must be at least 8 characters long and alphanumeric' });
  }

  try {
    const user = new User({ name, email, password });
    await user.save();

    const mailOptions = {
      from: 'weppso@outlook.com',
      to: email,
      subject: 'Thanks for Registering in Parking App',
      text: `Thanks for registering in Parking App. Your ID: ${email} and Password: ${password}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log('Error sending email:', error);
      } else {
        console.log('Email sent:', info.response);
      }
    });

    const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
    res.status(201).json({ message: 'User registered successfully', token });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ message: 'Email already exists' });
    }
    res.status(500).json({ message: 'Error registering user', error });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error });
  }
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('No token provided');
    return res.sendStatus(401);
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      console.log('Token verification failed:', err);
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};


app.post('/profile', authenticateToken, upload.single('profilePic'), async (req, res) => {
  const { name, age, vehicle, model, licensePlate, owner } = req.body;
  const profilePic = req.file ? req.file.path : null;

  console.log('Updating profile:', {
    name, age, vehicle, model, licensePlate, owner, profilePic
  });

  try {
    const user = await User.findOneAndUpdate(
      { email: req.user.email },
      { name, age, vehicle, model, licensePlate, owner, profilePic },
      { new: true }
    );

    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    console.log('Profile updated:', user);

    res.status(200).json({ message: 'Profile updated successfully', user });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ message: 'Error updating profile', error });
  }
});

app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching profile', error });
  }
});

// Get slots for a specific location
app.get('/slots/:location', authenticateToken, async (req, res) => {
  const { location } = req.params;
  try {
    const slots = await Slot.findOne({ parkingLocation: location });
    if (!slots) {
      return res.status(404).json({ message: 'Slots not found for this location' });
    }

    const currentTime = new Date();
    const reservations = await Reservation.find({
      parkingLocation: location,
      startTime: { $lte: currentTime },
      endTime: { $gte: currentTime }
    });

    slots.slots.forEach(slot => {
      slot.unavailable = reservations.some(reservation => 
        reservation.selectedSlots.some(selectedSlot => selectedSlot.id === slot.id));
    });

    res.status(200).json(slots);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching slots', error });
  }
});



// Reservation and Slot update API
app.post('/reserve', authenticateToken, async (req, res) => {
  try {
    const { vehicleName, vehicleType, parkingLocation, selectedSlots, date, startTime, endTime, totalCharges } = req.body;
    const userEmail = req.user.email;

    // Save the reservation
    const reservation = new Reservation({
      userEmail,
      vehicleName,
      vehicleType,
      parkingLocation,
      selectedSlots,
      date,
      startTime,
      endTime,
      totalCharges
    });

    await reservation.save();

    res.status(201).json({ message: 'Reservation successful', reservation });
  } catch (error) {
    res.status(500).json({ message: 'Error saving reservation', error });
  }
});

// Save reservation endpoint
app.post('/save-reservation', authenticateToken, async (req, res) => {
  const { reservationId, totalCharges } = req.body;
  try {
    const reservation = await Reservation.findById(reservationId);
    if (!reservation) {
      return res.status(404).json({ message: 'Reservation not found' });
    }

    // Update reservation with payment information or any other necessary details
    reservation.totalCharges = totalCharges;
    await reservation.save();

    res.status(201).json({ message: 'Reservation saved successfully' });
  } catch (error) {
    console.error('Error saving reservation:', error);
    res.status(500).json({ message: 'Error saving reservation', error });
  }
});

app.delete('/reserve/:id', authenticateToken, async (req, res) => {
  try {
    const reservationId = req.params.id;
    console.log(`Attempting to cancel reservation with ID: ${reservationId}`);

    const reservation = await Reservation.findById(reservationId);
    if (!reservation) {
      console.log(`Reservation with ID ${reservationId} not found`);
      return res.status(404).json({ message: 'Reservation not found' });
    }

    await Reservation.deleteOne({ _id: reservationId });
    console.log(`Reservation with ID ${reservationId} cancelled successfully`);

    res.status(200).json({ message: 'Reservation cancelled successfully' });
  } catch (error) {
    console.error('Error cancelling reservation:', error);
    res.status(500).json({ message: 'Error cancelling reservation', error });
  }
});

app.post('/create-payment-intent', async (req, res) => {
  try {
    const { amount } = req.body;
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount,
      currency: 'pkr',
    });

    res.send({
      clientSecret: paymentIntent.client_secret,
    });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

app.get('/reservations/:id', authenticateToken, async (req, res) => {
  try {
    const reservation = await Reservation.findById(req.params.id);
    if (!reservation) {
      return res.status(404).json({ message: 'Reservation not found' });
    }
    res.status(200).json(reservation);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching reservation', error });
  }
});

app.get('/slots', authenticateToken, async (req, res) => {
  try {
    const slots = await Slot.find({});
    res.status(200).json(slots);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching slots', error });
  }
});

app.get('/', (req, res) => {
  res.send('Hello');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Function to insert sample slot data
function insertSampleSlots() {
  const sampleSlots = [
    {
      parkingLocation: 'Nepa',
      slots: [
        { id: 'A01', selected: false, unavailable: false },
        { id: 'A02', selected: false, unavailable: false },
        { id: 'A03', selected: false, unavailable: false },
        { id: 'A04', selected: false, unavailable: false },
        { id: 'A05', selected: false, unavailable: false },
        { id: 'A06', selected: false, unavailable: false },
        { id: 'A07', selected: false, unavailable: false },
        { id: 'A08', selected: false, unavailable: false },
      ],
    },
    {
      parkingLocation: 'Gulshan',
      slots: [
        { id: 'A01', selected: false, unavailable: false },
        { id: 'A02', selected: false, unavailable: false },
        { id: 'A03', selected: false, unavailable: false },
        { id: 'A04', selected: false, unavailable: false },
        { id: 'A05', selected: false, unavailable: false },
      ],
    },
    {
      parkingLocation: 'Johar',
      slots: [
        { id: 'A01', selected: false, unavailable: false },
        { id: 'A02', selected: false, unavailable: false },
        { id: 'A03', selected: false, unavailable: false },
        { id: 'A04', selected: false, unavailable: false },
        { id: 'A05', selected: false, unavailable: false },
        { id: 'A06', selected: false, unavailable: false },
        { id: 'A07', selected: false, unavailable: false },
        { id: 'A08', selected: false, unavailable: false },
        { id: 'A09', selected: false, unavailable: false },
        { id: 'A10', selected: false, unavailable: false },
      ],
    },
  ];

  Slot.insertMany(sampleSlots)
    .then(() => {
      console.log('Sample slots inserted successfully');
    })
    .catch((error) => {
      console.error('Error inserting sample slots:', error);
    });
}
