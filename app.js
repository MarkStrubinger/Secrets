require('dotenv').config()
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const findOrCreate = require('mongoose-findorcreate');
const dotenv = require('dotenv');

const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
var GoogleStrategy = require('passport-google-oauth20').Strategy;

// Level 4 Hashing and Salting passwords using bcrypt
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

// Level 3 Hashing passwords using md5
// const md5 = require('md5');

// Level 2 Basic Password Encryption using mongoose-encryption
// const encrypt = require('mongoose-encryption');

// enables express.js scripts
const app = express();

// enables ejs template use
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

// session middleware is necessary for app to run
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

// For use with passport Authorization method
app.use(passport.initialize());
app.use(passport.session());


// Connects to the online mongoDB server, protects link using .env process
mongoose.connect(process.env.MONGOOSE_URL, {useNewUrlParser: true});

// defines userSchema, the mongoose Schematic to outline data object storage in the User model.
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

// Necessary plugins for passport to work correctly with userSchema
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Level 2 Basic Password Encryption using mongoose-encryption
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password'] });

// Creates User model, a database for user data
const User = new mongoose.model("User", userSchema);

// part of passport's authentication for the User database
passport.use(User.createStrategy());

// used to persist the user.id in the session
passport.serializeUser(function(user, done){
  done(null, user.id);
});

// retrieves user data from session
passport.deserializeUser(function(id, done){
  User.findById(id, function(err, user){
    done(err, user);
  });
});

// passport module, use method, enables the use of Google sign-in
// uses clientID and clientSecret hidden in .env file, and returns user to callbackURL when finished
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://secrets-markstrubinger.herokuapp.com/auth/google/secrets"
  },
  // runs function to create a cookie to keep user logged in
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    // Within the User collection, finds or creates an entry with 'googleId' key taking the unique profile.id as data
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// On get request for root page, render 'home' ejs template page
app.get("/", function(req, res){
  res.render("home");
});

// On route to google authorization,
// on a get request, run authenticate method, and pull only simple profile data for scope
app.route("/auth/google")
  .get(passport.authenticate('google', {
    scope: ["profile"]
  }));

// On get request for sign-in with google, run authenticate method from passport
app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect to secrets page.
      res.redirect('/secrets');
    });

// On get request for login page, run this function
app.get("/login", function(req, res){
  // render the login ejs template page
  res.render("login");
});

// On get request for register page, run this function
app.get("/register", function(req, res){
  // render the register ejs template page
  res.render("register");
});

// On get request to secrets page, run this function
app.get("/secrets", function(req, res){
  // From the User database, find all secret keys, return those that are NOT null
  // then run function labeling those secrets as foundUsers
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err) {
      console.log(err)
    } else {
      // if there are users with secrets, render secrets ejs page template
      // feed all ejs calls for 'usersWithSecrets' with 'foundUser' data
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

// On get request to submit page, run this function
app.get("/submit", function(req, res){
  // if user is authenticated, render the ejs submit page template
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    // if user is not authenticated, redirect to login
    res.redirect("/login");
  }
});

// On user post request to submit page, run function
app.post("/submit", function(req, res){
  // save user inputted data as variable submittedSecret
  const submittedSecret = req.body.secret;

  // for debug
  console.log(req.user.id);

  // run findById method on User collection, taking the request's user.id as data
  // then run function that labels any matching id as foundUser and uses it as input data
  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      // if there is a User with matching id, save into the User's secret key with var 'submittedSecret' data
      // then run a save on that User to save to the cluster, then redirect to secrets page to refresh.
      if (foundUser) {
        foundUser.secret = submittedSecret
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

// On get request for logout page, run logout and redirect to home page.
app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

// When information is posted by user on register page, run this function
app.post("/register", function(req, res){
  // using the register method on the User collection, takes inputted user data for authenticate method. Then run function.
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err){
      // if error, console log and redirect to register page
      console.log(err);
      res.redirect("/register");
      // else, run authenticate method to encrypt password and upon success, redirect to secrets page
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});

// When information is posted by user on login page, run this function
app.post("/login", function (req, res){

  // saves a variable 'user', which contains a mongoose model of a new 'User', saving the inputted username and password
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  // Upon login request, take saved user as input data into function
  req.login(user, function(err){
    // if error, console log and redirect to login page
    if (err){
      console.log(err);
      res.redirect("/login");
      // else, run the authentication process to reference saved password match, and redirect to secrets page if successful
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});

// For use with Heroku server deployment
let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function() {
  console.log("Server started successfully.");
});
