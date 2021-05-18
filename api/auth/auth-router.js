const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const buildToken = require('./token-builder')
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model')

router.post("/register", validateRoleName, (req, res, next) => {
  const {username, password, role_name} = req.body
  const hash = bcrypt.hashSync(password, 8)

  const trimmedRole = role_name.trim()
  Users.add({username, password: hash, role_name: trimmedRole})
  .then(user => {
    res.status(201).json(user)
  })
  .catch(next)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  let {username, password} = req.body

  Users.findBy({username})
  .then(([user]) => {
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = buildToken(user)
      res.status(200).json({
        message: `${user.username} is back!`,
        token
      })
    } else {
      res.status(401).json({
        message: `Invalid credentials`
      })
    }
  })
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
