require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "development_secret_change_me";

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["donor", "recipient", "admin"], required: true },
  phone: { type: String, default: "" },
  city: { type: String, default: "" },
  district: { type: String, default: "" },
  pincode: { type: String, default: "" },
  bloodGroup: { type: String, default: "" },
  available: { type: Boolean, default: true },
  verified: { type: Boolean, default: false },
  lastDonationDate: { type: Date, default: null }
}, { timestamps: true });

const requestSchema = new mongoose.Schema({
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  donor: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  bloodGroup: { type: String, required: true },
  units: { type: Number, default: 1, min: 1 },
  city: { type: String, required: true },
  district: { type: String, default: "" },
  pincode: { type: String, default: "" },
  hospital: { type: String, default: "" },
  message: { type: String, default: "" },
  status: { type: String, enum: ["Pending", "Accepted", "Declined", "Completed"], default: "Pending" }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);
const BloodRequest = mongoose.model("BloodRequest", requestSchema);

function tokenFor(user) {
  return jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
}
function safeUser(user) {
  const u = user.toObject ? user.toObject() : user;
  delete u.password;
  return u;
}
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ message: "Please log in to continue." });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Your session expired. Please log in again." });
  }
}
const allow = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ message: "You do not have permission for this action." });
  next();
};
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get("/api/health", (req, res) => res.json({ status: "ok", app: "LifeLink Blood Donation Portal" }));

app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const { name, email, password, role, phone, city, district, pincode, bloodGroup } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ message: "Name, email, password and role are required." });
  if (!["donor", "recipient"].includes(role)) return res.status(400).json({ message: "Choose donor or recipient registration." });
  if (password.length < 8) return res.status(400).json({ message: "Password must contain at least 8 characters." });
  if (role === "donor" && (!bloodGroup || !city || !phone)) return res.status(400).json({ message: "Donors must provide blood group, phone and city." });
  if (await User.findOne({ email: email.toLowerCase() })) return res.status(409).json({ message: "An account with this email already exists." });
  const passwordHash = await bcrypt.hash(password, 12);
  const user = await User.create({ name, email, password: passwordHash, role, phone, city, district, pincode, bloodGroup, verified: role === "recipient" });
  res.status(201).json({ token: tokenFor(user), user: safeUser(user), message: "Account created successfully." });
}));

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email: String(email || "").toLowerCase() });
  if (!user || !(await bcrypt.compare(password || "", user.password))) return res.status(401).json({ message: "Invalid email or password." });
  res.json({ token: tokenFor(user), user: safeUser(user), message: "Welcome back." });
}));

app.get("/api/auth/me", auth, asyncRoute(async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  if (!user) return res.status(404).json({ message: "Account not found." });
  res.json({ user });
}));

app.post("/api/donors", auth, allow("donor"), asyncRoute(async (req, res) => {
  const updates = ["phone", "city", "district", "pincode", "bloodGroup", "lastDonationDate"];
  updates.forEach(k => { if (req.body[k] !== undefined) req.user[k] = req.body[k]; });
  const user = await User.findByIdAndUpdate(req.user.id, Object.fromEntries(updates.filter(k => req.body[k] !== undefined).map(k => [k, req.body[k]])), { new: true, runValidators: true }).select("-password");
  res.status(201).json({ user, message: "Donor profile saved." });
}));

app.get("/api/donors/search", auth, allow("recipient", "admin"), asyncRoute(async (req, res) => {
  const { bloodGroup, city, district, pincode } = req.query;
  const filter = { role: "donor", available: true, verified: true };
  if (bloodGroup) filter.bloodGroup = bloodGroup;
  if (city) filter.city = new RegExp(String(city).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
  if (district) filter.district = new RegExp(String(district).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
  if (pincode) filter.pincode = String(pincode);
  const donors = await User.find(filter).select("name phone city district pincode bloodGroup available lastDonationDate verified").sort({ createdAt: -1 }).limit(100);
  res.json({ donors });
}));

app.put("/api/donors/status/:id", auth, allow("donor"), asyncRoute(async (req, res) => {
  if (req.params.id !== req.user.id) return res.status(403).json({ message: "You can update only your own availability." });
  const user = await User.findByIdAndUpdate(req.user.id, { available: Boolean(req.body.available) }, { new: true }).select("-password");
  res.json({ user, message: "Availability updated." });
}));

app.post("/api/requests", auth, allow("recipient"), asyncRoute(async (req, res) => {
  const { bloodGroup, units, city, district, pincode, hospital, message, donorId } = req.body;
  if (!bloodGroup || !city) return res.status(400).json({ message: "Blood group and city are required." });
  if (donorId) {
    const donor = await User.findOne({ _id: donorId, role: "donor", available: true, verified: true, bloodGroup });
    if (!donor) return res.status(400).json({ message: "This donor is not currently available for the selected blood group." });
  }
  const request = await BloodRequest.create({ recipient: req.user.id, donor: donorId || null, bloodGroup, units: Number(units) || 1, city, district, pincode, hospital, message });
  res.status(201).json({ request, message: "Blood request sent." });
}));

app.get("/api/requests/my", auth, allow("recipient"), asyncRoute(async (req, res) => {
  const requests = await BloodRequest.find({ recipient: req.user.id }).populate("donor", "name phone city bloodGroup").sort({ createdAt: -1 });
  res.json({ requests });
}));

app.get("/api/requests/donor/:donorId", auth, allow("donor"), asyncRoute(async (req, res) => {
  if (req.params.donorId !== req.user.id) return res.status(403).json({ message: "You can view only your own requests." });
  const requests = await BloodRequest.find({ $or: [{ donor: req.user.id }, { donor: null, bloodGroup: (await User.findById(req.user.id)).bloodGroup, city: (await User.findById(req.user.id)).city }] })
    .populate("recipient", "name phone city district").sort({ createdAt: -1 });
  res.json({ requests });
}));

app.put("/api/requests/:id", auth, allow("donor"), asyncRoute(async (req, res) => {
  const { status } = req.body;
  if (!["Accepted", "Declined", "Completed"].includes(status)) return res.status(400).json({ message: "Invalid request status." });
  const request = await BloodRequest.findById(req.params.id);
  if (!request) return res.status(404).json({ message: "Request not found." });
  const donor = await User.findById(req.user.id);
  if (request.donor && String(request.donor) !== req.user.id) return res.status(403).json({ message: "This request belongs to another donor." });
  if (!request.donor && (request.bloodGroup !== donor.bloodGroup || request.city.toLowerCase() !== donor.city.toLowerCase())) return res.status(403).json({ message: "This request is not matched to your profile." });
  request.donor = req.user.id;
  request.status = status;
  await request.save();
  res.json({ request, message: `Request ${status.toLowerCase()}.` });
}));

app.get("/api/admin/users", auth, allow("admin"), asyncRoute(async (req, res) => {
  const users = await User.find().select("-password").sort({ createdAt: -1 });
  res.json({ users });
}));
app.get("/api/admin/requests", auth, allow("admin"), asyncRoute(async (req, res) => {
  const requests = await BloodRequest.find().populate("recipient", "name email phone").populate("donor", "name phone").sort({ createdAt: -1 });
  res.json({ requests });
}));
app.put("/api/admin/users/:id/verify", auth, allow("admin"), asyncRoute(async (req, res) => {
  const user = await User.findOneAndUpdate({ _id: req.params.id, role: "donor" }, { verified: Boolean(req.body.verified) }, { new: true }).select("-password");
  if (!user) return res.status(404).json({ message: "Donor not found." });
  res.json({ user, message: user.verified ? "Donor verified." : "Donor verification removed." });
}));
app.delete("/api/admin/users/:id", auth, allow("admin"), asyncRoute(async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  await BloodRequest.deleteMany({ $or: [{ recipient: req.params.id }, { donor: req.params.id }] });
  res.json({ message: "User and related request records removed." });
}));

app.use((err, req, res, next) => {
  console.error(err);
  if (err.code === 11000) return res.status(409).json({ message: "Email address already registered." });
  res.status(500).json({ message: "Something went wrong on the server." });
});

async function seedAdmin() {
  const email = process.env.ADMIN_EMAIL || "admin@lifelink.local";
  const existing = await User.findOne({ email });
  if (!existing) {
    const password = await bcrypt.hash(process.env.ADMIN_PASSWORD || "Admin@12345", 12);
    await User.create({ name: process.env.ADMIN_NAME || "Portal Admin", email, password, role: "admin", verified: true });
    console.log(`Admin created: ${email}`);
  }
}
mongoose.connect(process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/lifelink_blood_portal")
  .then(async () => {
    console.log("MongoDB connected");
    await seedAdmin();
    app.listen(PORT, () => console.log(`LifeLink running at http://localhost:${PORT}`));
  })
  .catch(err => { console.error("MongoDB connection failed:", err.message); process.exit(1); });
