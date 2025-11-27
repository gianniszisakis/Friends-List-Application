const express = require("express");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const routes = require("./router/friends.js");

let users = [];

//Check if a user with the given username exists
const doesExist = (username) => {
  let usersWithUsername = users.filter((user) => {
    return user.username === username;
  });

  if (usersWithUsername.length > 0) {
    return true;
  } else {
    return false;
  }
};

//check if the user with the given username and password exists
const authenticatedUser = (username, password) => {
  const usersWithUsernameAndPassword = users.filter((user) => {
    return user.username === username && user.password === password;
  });

  if (usersWithUsernameAndPassword?.length > 0) {
    return true;
  } else {
    return false;
  }
};

const app = express();
//create and use a session object with user-defined secret, as a middleware to intercept the requests and ensure that the session is valid before processing the request.
app.use(
  session(
    { secret: "fingerprint" },
    (resave = true),
    (saveUninitialized = true)
  )
);
app.use(express.json());

//middleware to authenticate requests to /friends endpoint
app.use("/friends", function auth(req, res, next) {
  //check if the user is logged in and has valid access token
  if (req.session.authorization) {
    let token = req.session.authorization["accessToken"];

    //verify JWT token
    jwt.verify(token, "access", (err, user) => {
      if (!err) {
        req.user = user;
        next(); //proceed to next middleware
      } else {
        return res.status(403).json({ message: "User not authenticated" });
      }
    });
  } else {
    return res.status(403).json({ message: "User not logged in" });
  }
});

//Login endpoint
app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  //Check if username or password is missing
  if (!username || !password) {
    return res.status(403).json({ message: "Username or password missing" });
  }

  //Authenticate user
  if (authenticatedUser(username, password)) {
    //Generate JWT token
    let accessToken = jwt.sign(
      {
        data: password,
      },
      "access",
      { expiresIn: 60 * 60 }
    );

    //Store access token and username in session
    req.session.authorization = {
      accessToken,
      username,
    };
    return res.send(200).send("User logged in");
  } else {
    return res.send(208).send("Wrong username or password");
  }
});

//register a new user
app.post("/register", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  //check if both username and password are provided
  if (username && password) {
    //check if the user already exists
    if (!doesExist(username)) {
      //add the new user to the users array
      users.push({ username: username, password: password });
      return res.status(200).json({ message: "User registered" });
    } else {
      return res.status(404).json({ message: "User already exists" });
    }
  }

  return res.status(404).json({ message: "Unable to register user" });
});

const PORT = 5000;

app.use("/friends", routes);

app.listen(PORT, () => console.log("Server is running"));
