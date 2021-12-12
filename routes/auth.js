const { Router } = require('express');
const router = new Router();

// To be able to save users in the database, we have to require user model. 
const User = require('../models/User.model');

// bcryptjs
const bcryptjs = require('bcryptjs');
const saltRounds = 10;

// GET route ==> to display the signup form to users
router.get('/signup', (req, res) => res.render('auth/signup'));

// POST route ==> to process form data
router.post('/signup', (req, res, next) => {
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

// render the User's profile page
router.get('/userProfile', (req, res) => res.render('users/user-profile'));

module.exports = router;