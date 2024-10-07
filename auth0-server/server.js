require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const { auth } = require("express-oauth2-jwt-bearer");

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose
  .connect(process.env.DATABASE_URL)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Could not connect to MongoDB", err));

// User Schema
const userSchema = new mongoose.Schema({
  auth0Id: String,
  todos: [{ title: String, completed: Boolean }],
});

const User = mongoose.model("User", userSchema);

// Auth0 JWT Middleware
const jwtCheck = auth({
  audience: "http://localhost:3033", // Укажите правильный audience
  issuerBaseURL: "https://dev-w4mhfi5sg7rm3bcl.us.auth0.com/",
  tokenSigningAlg: "RS256",
});

app.use((req, res, next) => {
  console.log("Authorization Header:", req.headers.authorization);
  console.log("Headers:", req.headers);
  next();
});

// Enforce JWT authentication on all routes
app.use(jwtCheck);

// Routes
app.get("/api/todos", async (req, res) => {
  const userId = req.auth.payload.sub;
  try {
    let user = await User.findOne({ auth0Id: userId });
    if (!user) {
      user = new User({ auth0Id: userId, todos: [] });
      await user.save();
    }
    res.json({ todos: user.todos }); // Возвращаем объект с ключом "todos"
  } catch (err) {
    res.status(500).send("Server error");
  }
});

app.get("/authorized", function (req, res) {
  res.send("Secured Resource");
});

app.post("/api/register", async (req, res) => {
  const userId = req.auth.payload.sub;

  console.log("User ID from JWT:", userId);

  try {
    let user = await User.findOne({ auth0Id: userId });
    if (!user) {
      user = new User({ auth0Id: userId, todos: [] });
      await user.save();
    }
    res.status(200).send("User registered successfully");
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).send("Server error");
  }
});

app.post("/api/todos", async (req, res) => {
  const userId = req.auth.payload.sub;
  const { title } = req.body;

  try {
    const user = await User.findOne({ auth0Id: userId });
    if (user) {
      user.todos.push({ title, completed: false });
      await user.save();
      res.json({ todos: user.todos }); // Возвращаем объект с ключом "todos"
    } else {
      res.status(404).send("User not found");
    }
  } catch (err) {
    res.status(500).send("Server error");
  }
});

app.put("/api/todos/:id", async (req, res) => {
  const userId = req.auth.payload.sub;
  const { id } = req.params;
  const { title, completed } = req.body;

  try {
    const user = await User.findOne({ auth0Id: userId });
    if (user) {
      const todo = user.todos.id(id);
      if (todo) {
        todo.title = title;
        todo.completed = completed;
        await user.save();
        res.json({ todos: user.todos }); // Возвращаем объект с ключом "todos"
      } else {
        res.status(404).send("Todo not found");
      }
    } else {
      res.status(404).send("User not found");
    }
  } catch (err) {
    res.status(500).send("Server error");
  }
});

app.delete("/api/todos/:id", async (req, res) => {
  const userId = req.auth.payload.sub;
  const { id } = req.params;

  try {
    const user = await User.findOne({ auth0Id: userId });
    if (user) {
      // Найдём индекс задачи с указанным _id
      const todoIndex = user.todos.findIndex(
        (todo) => todo._id.toString() === id
      );
      if (todoIndex > -1) {
        user.todos.splice(todoIndex, 1); // Удаляем задачу из массива todos по индексу
        await user.save();
        res.json({ todos: user.todos }); // Возвращаем обновленный список задач
      } else {
        res.status(404).send("Todo not found");
      }
    } else {
      res.status(404).send("User not found");
    }
  } catch (err) {
    console.error("Error deleting todo:", err);
    res.status(500).send("Server error");
  }
});

// Start server
const PORT = process.env.PORT || 3033;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
