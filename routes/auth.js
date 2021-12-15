const { Router } = require('express');
const router = new Router();

// To be able to save users in the database, we have to require user model. 
const User = require('../models/User.model');

// bcryptjs
const bcryptjs = require('bcryptjs');
const saltRounds = 10;

// require auth middleware
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');

// SIGNUP

// GET route ==> to display the signup form to users
router.get('/signup', isLoggedOut, (req, res) => res.render('auth/signup'));

// POST route ==> to process form data
router.post('/signup', isLoggedOut, (req, res, next) => {
    // console.log('The form data: ', req.body);

    const { username, password } = req.body;
 
  bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
        return User.create({
            username,
            passwordHash: hashedPassword
            // passwordHash --> this is the key from the User model
            // hashedPassword --> this is placeholder (how we named returning value from the previous method (.hash()))
        });
    })
    .then(userFromDB => {
        console.log('Newly created user is: ', userFromDB);
        // The user is redirected to their fake profile page if they submit the form successfully and the new user gets created.
        res.redirect('/userProfile');
    })
    .catch(error => next(error));
  });


// LOGIN

// GET route ==> to display the login form to users
router.get('/login', isLoggedOut, (req, res) => res.render('auth/login'));

// POST login route ==> to process form data
router.post('/login', isLoggedOut, (req, res, next) => {
  console.log('SESSION =====> ', req.session);

  const { username, password } = req.body;
 
  if (username === '' || password === '') {
    res.render('auth/login', {
      errorMessage: 'Please enter both, username and password to login.'
    });
    return;
  }
 
  User.findOne({ username })     // <== check if there's user with the provided username
    .then(user => {     // response from DB - doesn't matter if found or not)
                        // <== "user" here is just a placeholder and represents the response from the DB
      if (!user) {      // <== if there's no user with provided username, notify the user who is trying to login
        res.render('auth/login', { errorMessage: 'Username is not registered. Try with other username.' });
        return;
      } 
      
      // if there's a user, compare provided password
      // with the hashed password saved in the database
        else if (bcryptjs.compareSync(password, user.passwordHash)) {
      // if the two passwords match, render the user-profile.hbs and pass the user object to this view
        // res.render('users/user-profile', { user });

        //******* SAVE THE USER IN THE SESSION ********//
        req.session.currentUser = user;
        res.redirect('/userProfile');
      } else {
      // if the two passwords DON'T match, render the login form again and send the error message to the user
        res.render('auth/login', { errorMessage: 'Incorrect password.' });
      }
    })
    .catch(error => next(error));     // error handler in case some error occurred while getting the data from the DB)
});


// LOGOUT

router.post('/logout', isLoggedIn, (req, res, next) => {
  req.session.destroy(err => {
    if (err) next(err);
    res.redirect('/');
  });
});

// render the User's profile page
router.get('/userProfile', isLoggedIn, (req, res) => {
  res.render('users/user-profile', { userInSession: req.session.currentUser });
});

module.exports = router;