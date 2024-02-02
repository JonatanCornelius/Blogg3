const express = require("express");
const session = require("express-session");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const helmet = require("helmet");
const MongoDBStore = require("connect-mongodb-session")(session);
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy; // Lägg till Local Strategy
const GitHubStrategy = require("passport-github").Strategy;
const sanitizeHtml = require("sanitize-html");
const mongoSanitize = require("express-mongo-sanitize");
const http = require("http");
const socketIo = require("socket.io");
const crypto = require('crypto');
const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const PORT = 8000;
const dotenv = require('dotenv')
dotenv.config()

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "script-src": ["self", "https://cdn.socket.io"],
      "script-src-elem": ["self", "https://cdn.socket.io", "'unsafe-inline'"],
    },
  })
);

app.use(mongoSanitize());

app.use((req, res, next) => {
  req.io = io;
  next();
});

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 45 * 60 * 1000,
      sameSite: 'strict',
    },
  })
);

function verifyCsrfToken(req, res, next) {
  if (req.session.csrfToken === req.body._csrf) {
    next();
  } else {
    res.status(200).send("Invalid CSRF-token");
  }
}


const store = new MongoDBStore({
  uri: "mongodb://localhost/cornelius",
  collection: "sessions",
  expires: 1000 * 60 * 20,
  connectionOptions: {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
});

mongoose.connect("mongodb://localhost/cornelius", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  userRole: { type: String, default: "user" },
});

const postSchema = new mongoose.Schema({
  title: String,
  content: {
    type: String,
    set: (value) =>
      sanitizeHtml(value, {
        allowedTags: ["b", "i", "em", "strong", "a", "u"],
        allowedAttributes: {},
      }),
  },
  userId: mongoose.Schema.Types.ObjectId,
  timestamp: { type: Date, default: Date.now },
  signature: String,
  comments: [
    {
      userId: mongoose.Schema.Types.ObjectId,
      username: String,
      content: String,
      timestamp: { type: Date, default: Date.now },
    },
  ],
  likes: [
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
      username: String, 
      timestamp: { type: Date, default: Date.now },
    },
  ],
});

const User = mongoose.model("User", userSchema);
const Post = mongoose.model("Post", postSchema);

Post.prototype.addComment = async function (userId, username, content) {
  this.comments.push({
    userId: userId,
    username: username,
    content: content,
  });
  await this.save();
};

Post.prototype.addLike = async function (userId) {
  const alreadyLiked = this.likes.some((like) => like.userId.equals(userId));

  if (!alreadyLiked) {
    this.likes.push({
      userId: userId,
    });
    await this.save();
  }
};

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);

    if (user) {
      // Här lägger du till CSRF-token och loggedIn-flaggan i sessionen
      user.csrfToken = crypto.randomBytes(64).toString("hex");
      user.loggedIn = true;
    }

    done(null, user);
  } catch (error) {
    console.error(error);
    done(error);
  }
});

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username });

      if (!user || !bcrypt.compareSync(password, user.password)) {
        return done(null, false, {
          message: "Incorrect username or password.",
        });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);

passport.use(
  new GitHubStrategy(
    {
      clientID: "25a0d1b9fe49a9c4f827",
      clientSecret: process.env.GITHUB_SECRET_KEY,
      callbackURL: "http://localhost:8000/auth/github/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const user = await User.findOne({ githubId: profile.id });

        if (user) {
          return done(null, user);
        }

        const newUser = new User({
          username: profile.username,
          githubId: profile.id,
        });

        await newUser.save();
        return done(null, newUser);
      } catch (error) {
        return done(error);
      }
    }
  )
);


app.get("/auth/github", passport.authenticate("github"));

app.get(
  "/auth/github/callback",
  passport.authenticate("github", {
    successRedirect: "/home",
    failureRedirect: "/login", // You can change this to handle failures appropriately
  })
);

const isLoggedIn = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
};

app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post(
  "/login",
  (req, res, next) => {
    // Generera och lagra CSRF-token
    const csrfToken = crypto.randomBytes(64).toString("hex");
    req.session.csrfToken = csrfToken;

    // Fortsätt till autentiseringsprocessen
    next();
  },
  passport.authenticate("local", {
    successRedirect: "/home",
    failureRedirect: "/login",
    failureFlash: true,  // Visa autentiseringsfel i sessionen
  })
);


app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).render("register", { error: "Username is already taken" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username: req.body.username,
      password: hashedPassword,
    });

    await user.save();
    res.redirect("/login");
  } catch (error) {
    console.error(error);
    res.status(500).render("register", { error: "Internal Server Error" });
  }
});


app.get("/home", isLoggedIn, async (req, res) => {
  try {
    const user = req.user;
    const posts = await Post.find();

    posts.forEach((post) => {
      post.alreadyLiked = post.likes.some((like) =>
        like.userId.equals(user._id)
      );
    });

    res.render("home", { user, posts, alreadyLiked: false });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});


app.get("/newpost", isLoggedIn, (req, res) => {
  const emptyPost = {
    title: "",
    content: "",
    comments: [],
    likes: [],
  };

  res.render("newpost", { post: emptyPost });
});

app.post("/newpost", isLoggedIn, async (req, res) => {
  const { title, content } = req.body;
  const user = req.user;

  const post = new Post({
    title: title,
    content: content,
    userId: user._id,
    signature: user.username,
  });

  await post.save();
  res.redirect("/home");
});

app.post("/comment/:postId", isLoggedIn, async (req, res) => {
  try {
    const postId = req.params.postId;
    const content = req.body.content;
    const userId = req.user._id;
    const username = req.user.username;

    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).send("Post not found");
    }

    await post.addComment(userId, username, content);

    // Skicka notis via WebSocket
    req.io.emit("comment", { postId, username });

    res.redirect("/home");
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});


app.post("/like/:postId", isLoggedIn, async (req, res) => {
  try {
    const postId = req.params.postId;
    const userId = req.user._id;

    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).send("Post not found");
    }

    const alreadyLiked = post.likes.some((like) => like.userId.equals(userId));

    if (!alreadyLiked) {
      // Sparar användarnamnet för den som gillade inlägget
      const likeData = {
        userId: userId,
        username: req.user.username,
      };

      post.likes.push(likeData);
      await post.save();

      req.io.emit("like", { postId, username: req.user.username });

      res.redirect("/home");
    } else {
      console.log("User has already liked this post.");
      res.status(400).send("You have already liked this post.");
    }
  } catch (error) {
    console.error("Error liking post:", error);
    res.status(500).send("Internal Server Error");
  }
});


app.post("/deletepost/:id", isLoggedIn, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user._id;

  try {
    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).send("Post not found");
    }

    // Kontrollera om användaren är admin eller författaren till inlägget
    if (req.user.userRole === "admin" || post.userId.equals(userId)) {
      await Post.findByIdAndDelete(postId);
      res.redirect("/home");
    } else {
      res.status(403).send("Unauthorized");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});


app.get("/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy((err) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else {
        res.redirect("/login");
      }
    });
  });
});

io.on("connection", (socket) => {
  console.log("A user connected");

  socket.on("disconnect", () => {
    console.log("User disconnected");
  });

});


server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
