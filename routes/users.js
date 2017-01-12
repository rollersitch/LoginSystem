var express = require('express');
var router = express.Router();

var User = require('../models/users');

var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;


/*
function ensureAuthenticated2(req,res,next) {
	if(req.isAuthenticated()) {
		return next();
	}
	else {
		req.flash('error_msg', 'You are not logged in');
		res.redirect('/users/login');
	}
}
*/
router.get('/register',function(req,res) {
	res.render('register');
});

router.get('/login', function(req,res) {
	res.render('login');
});

router.post('/register', function(req,res) {
	var name = req.body.name;
	var email = req.body.email;
	var username = req.body.username;
	var password = req.body.password;
	var password2 = req.body.password2;

	req.checkBody('name', 'Name is required').notEmpty();
	req.checkBody('email','Formato email non valido').isEmail();
	req.checkBody('email','Campo Email Vuoto').notEmpty();
	req.checkBody('username','Solo caratteri alfanumerici per Username').isAlphanumeric();
	req.checkBody('password','Lunghezza compresa fra 5 e 30 caratteri').len(5,30);
	req.checkBody('password2','Passwords do not match').equals(req.body.password);

	req.getValidationResult().then(function(result) {
		if (result.isEmpty()) {
			var newUser = new User({
				name: name,
				email: email,
				username: username,
				password: password
			});

			User.createUser(newUser, function(err, user) {
				if(err) {
					throw err;
				}
				else {
					console.log(user);
				}
			});

			req.flash('success_msg', 'You are registered and can now login');

			res.redirect('/users/login');
		}
		else {
			console.log("NO");
			res.render('register', {
				errors: result.array()
			});
		}
	});
});

passport.use(new LocalStrategy(
	function(username, password, done) {
		User.getUserByUsername(username, function(err,user) {
			if(err) {
				throw err;
			}
			else {
				if(!user) {
					return done(null, false, {message: 'Unknown User'});
				}
				User.comparePassword(password, user.password, function(err,isMatch) {
					if(err) {
						throw err;
					}
					if(isMatch) {
						return done(null, user);
					}
					else {
						return done(null, false, {message: 'Invalid Password'});
					}
				});
			}
		});
	}));

passport.serializeUser(function(user,done) {
	done(null,user.id);
});

passport.deserializeUser(function(id,done) {
	User.getUserById(id, function(err, user) {
		done(err,user);
	});
});


router.post('/login',
	passport.authenticate('local',
							{
								successRedirect: '/',
								failureRedirect: "/users/login",
								failureFlash: true
							}),
							function(req,res) {
								res.redirect('/');
							});



router.get('/logout', function (req,res) {
	req.logout();
	req.flash('success_msg', 'You are logged out');

	res.redirect('/users/login');
});

module.exports = router;