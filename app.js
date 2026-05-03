require("./utils.js");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const saltRounds = 12;
const dns = require("node:dns/promises");

dns.setServers(["1.1.1.1", "8.8.8.8"]);
const app = express();
const Joi = require("joi");

app.use(express.urlencoded({ extended: false }));

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const { database } = include("databaseConnection");
/*
(async () => {
  await database.connect();
})();
*/
const userCollection = database.db(mongodb_database).collection("users");

let mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

const PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000;

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    resave: true,
    saveUninitialized: false,
    cookie: { maxAge: expireTime },
  }),
);

app.get("/", (req, res) => {
  if (req.session && req.session.authenticated) {
    res.send(`
            Hello, ${req.session.name}
            <form method="get" action="/members">
                <button>Go to Members Area</button>
            </form>
            <form method="get" action="/logout">
                <button>Logout</button>
            </form>    
            `);
  } else {
    res.send(`
            <form method="get" action="/signup">
                <button>Sign up</button>
            </form>
            <form method="get" action="/login">
                <button>Log in</button>
            </form>    
            `);
  }
});

app.get("/signup", (req, res) => {
  if (req.session && req.session.authenticated) {
    res.redirect("/members");
  } else {
    res.send(`
      create user
      <form method="post" action="/signupSubmit">
          <input name="name" type="text" placeholder="name">
          <br>
          <input name="email" type="email" placeholder="email">
          <br>
          <input name="password" type="password" placeholder="password">
          <br>
          <button>Submit</button>
      </form>  
    `);
  }
});

app.get("/login", (req, res) => {
  if (req.session && req.session.authenticated) {
    res.redirect("/members");
  } else {
    res.send(`
      log in
      <form method="post" action="/loginSubmit">
          <input name="email" type="email" placeholder="email">
          <br>
          <input name="password" type="password" placeholder="password">
          <br>
          <button>Submit</button>
      </form>  
    `);
  }
});

app.post("/loginSubmit", async (req, res) => {
  let email = req.body.email;
  let password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().max(50).required(),
    password: Joi.string().min(8).max(100).required(),
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error) {
    res.send(`
        ${validationResult.error.message}
        <br><br>
        <a href="/login">Try again</a>`);
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ name: 1, email: 1, password: 1, _id: 1 })
    .toArray();
  if (result.length != 1) {
    res.send(`
        User not found.
        <br><br>
        <a href="/login">Try again</a>`);
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.name = result[0].name;
    req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
  } else {
    res.send(`
        Incorrect password.
        <br><br>
        <a href="/login">Try again</a>`);
    return;
  }
});

app.post("/signupSubmit", async (req, res) => {
  let name = req.body.name;
  let email = req.body.email;
  let password = req.body.password;

  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().max(50).required(),
    password: Joi.string().min(8).max(100).required(),
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error) {
    res.send(`
        ${validationResult.error.message}
        <br><br>
        <a href="/signup">Try again</a>`);
    return;
  }
  const existingUser = await userCollection.findOne({ email: email });

  if (existingUser) {
    res.send(`
        Email already exists. Please use another email.
        <br><br>
        <a href="/signup">Try again</a>`);
    return;
  }

  let hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({
    name: name,
    email: email,
    password: hashedPassword,
  });
  req.session.authenticated = true;
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;
  res.redirect("/members");
});

app.get("/members", (req, res) => {
  if (req.session && req.session.authenticated) {
    let num = Math.floor(Math.random() * 3) + 1;
    res.send(`
      <h1>Hello, ${req.session.name}</h1>
      <img src="image-${num}.jpg" alt="Random Image">
      <form method="get" action="/logout">
        <button>Sign out</button>
      </form>  
      `);
  } else {
    res.redirect("/");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.use(express.static(__dirname + "/public"));

app.use((req, res) => {
  res.status(404);
  res.send("Page not found - 404");
});

app.use((err, req, res, next) => {
  console.error(err.stack);

  res.status(500).json({
    error: "Internal server error",
  });
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
