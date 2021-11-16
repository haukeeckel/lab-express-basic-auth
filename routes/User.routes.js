const router = require('express').Router();
const UserModel = require('../models/User.model');
const bcrypt = require('bcryptjs');

router.get('/signup', (_, res) => {
  res.render('auth/signup');
});

router.post('/signup', (req, res, next) => {
  const { username, password } = req.body;

  if (username == '' || password == '') {
    res.render('auth/signup', { error: 'Please enter all fields' });
    return;
  }

  let passRegEx = new RegExp(
    '(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})'
  );
  if (!passRegEx.test(password)) {
    res.render('auth/signup.hbs', {
      error:
        'Please enter Minimum eight characters, at least one letter and one number for your password',
    });
    return;
  }

  let salt = bcrypt.genSaltSync(12);
  let hash = bcrypt.hashSync(password, salt);

  UserModel.create({ username, password: hash })
    .then(() => {
      res.redirect('/');
    })
    .catch((err) => {
      if (err.code == 11000) {
        res.render('auth/signup', { isTaken: true });
        return;
      }
      next(err);
    });
});

router.get('/signin', (_, res) => {
  res.render('auth/signin');
});

router.post('/signin', (req, res, next) => {
  const { username, password } = req.body;

  UserModel.find({ username })
    .then((user) => {
      if (user.length) {
        let userObj = user[0];

        let checkPW = bcrypt.compareSync(password, userObj.password);

        if (checkPW) {
          req.session.myProperty = userObj;
          res.redirect('/private');
        } else {
          res.render('auth/signin', {
            error: 'You entered a wrong Password',
          });
          return;
        }
      } else {
        res.render('auth/signin', {
          error: 'You entered a wrong Username',
        });
        return;
      }
    })
    .catch((err) => {
      next(err);
    });
});

const checkLogIn = (req, res, next) => {
  if (req.session.myProperty) {
    next();
  } else {
    res.redirect('/signin');
  }
};

router.get('/main', checkLogIn, (req, res, next) => {
  res.render('auth/main');
});

router.get('/private', checkLogIn, (req, res, next) => {
  let { username } = req.session.myProperty;
  res.render('auth/private', { username });
});

router.get('/logout', (req, res, next) => {
  req.session.destroy();
  res.redirect('/signin');
});

module.exports = router;
