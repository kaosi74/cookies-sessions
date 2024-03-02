import express from "express";
import { dirname } from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bycryptjs from "bcryptjs";
import bodyParser from "body-parser";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";

import { User } from "./models/User.js";
dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("DB connected successfully");
  });

const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));

const __dirname = dirname(fileURLToPath(import.meta.url));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

app.get("/signUp", (req, res) => {
  res.sendFile(__dirname + "/public/signUp.html");
});

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});

app.get("/site", (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
    res.sendFile(__dirname + "/public/site.html");
  } else {
    res.sendFile(__dirname + "/public/login.html");
  }
});

app.post("/signUp", (req, res) => {
  const { username, email, password } = req.body;
  if (username == "" || email == "" || password == "") {
    res.json({
      status: "Failed",
      info: "Empty credentials submitted",
    });
  } else if (password.length < 8) {
    res.json({
      status: "Failed",
      info: "Password is too short",
    });
  } else {
    User.findOne({ username, email }).then((result) => {
      if (result) {
        res.json({
          status: "Failed",
          info: "User with User Name or Email already exists",
        });
      } else {
        bycryptjs.hash(password, saltRounds, async (err, hash) => {
          if (err) {
            res.json({
              status: "Failed",
              info: err,
            });
          }

          const newUser = new User({
            username,
            email,
            password: hash,
          });
          newUser
            .save()
            .then(() => {
              res.sendFile(__dirname + "/public/login.html");
            })
            .catch((err) => {
              res.json({
                status: "Failed",
                info: err,
              });
            });
        });
      }
    });
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/site",
    failureRedirect: "/login",
  })
);

passport.use(
  new Strategy(async function verify(username, password, cb) {
    console.log(username);

    try {
      const result = await User.find({ username });
      const data = result[0];
      if (data) {
        console.log(data);
        const userPass = data.password;
        bycryptjs.compare(password, userPass, (err, result) => {
          if (err) {
            return cb(err);
          } else {
            if (result) {
              return cb(null, data);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (error) {
      return cb(error);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, (req, res) => {
  console.log(`Server is running on port ${port}`);
});
