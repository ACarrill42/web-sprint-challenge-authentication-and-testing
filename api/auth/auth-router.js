const router = require('express').Router();
const jwt = require('jsonwebtoken');
const {jwtSecret} = require('../secrets');
const bcrypt = require('bcrypt');
const Users = require('./auth-model');

const {checkUsernameExists, checkBodyValidation, validateUserExsist} = require('../middleware')

router.post('/register', checkUsernameExists,checkBodyValidation , (req, res, next) => {

      const {username, password} = req.body
      const hash = bcrypt.hashSync(password, 8)

      Users.add({username, password:hash})
        .then(newUser=>{
          res.status(201).json(newUser)
        })
        .catch(next)


      
});

router.post('/login',checkBodyValidation,validateUserExsist, (req, res, next) => {
  if(bcrypt.compareSync(req.body.password, req.user.password)){
    const token = makeToken(req.user)
    res.json({
      message: `${req.user.username} is back!`,
      token,
    })

  }else{next({status: 401, message: 'Invalid credentials'})}

});


function makeToken(user){
  const payload = {
    subject:user.id,
    username:user.username
  }
  const options = {
    expiresIn: "500s"
  }
  return jwt.sign(payload,jwtSecret,options)
}

module.exports = router;
