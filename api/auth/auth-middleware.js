const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require('../users/users-model')

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if(token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        next({
          status: 401,
          message: `Token invalid`
        })
      } else {
        req.decodedJwt = decoded
        next()
      } 
    }) 
  } else {
    next({
      status: 401,
      message: `Token required`
    })
  }
}

const only = role_name => (req, res, next) => {
  const decodedToken = req.decodedJwt
  if (decodedToken.role_name === role_name) {
    next()
  } else {
    next({
      status: 403,
      message: `This is not for you`
    })
  }
}


const checkUsernameExists = (req, res, next) => {
  const {username} = req.body
  User.findBy({username})
  .then(([user]) => {
    if (user) {
      next()
    } else {
      res.status(401).json({
        message: `Invalid credentials`
      })
    }
  })
}


const validateRoleName = (req, res, next) => {
  const {role_name} = req.body
  
  if(!role_name || role_name.trim() === "") {
    req.body.role_name = 'student'
    next()
  } else {
    User.findBy({role_name})
    .then(role => {
      const trimmedRole = role_name.trim()
      if (trimmedRole === "admin") {
        next({
          status: 422,
          message: `Role name can not be admin`,
        })
      } else if (trimmedRole.length > 32) {
        next({
          status: 422,
          message: `Role name can not be longer than 32 chars`
        })
      } else {
        next()
      }
    })
  } 
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
