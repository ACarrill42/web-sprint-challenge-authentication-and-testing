const db = require('./auth/auth-model')

const checkUsernameExists = async(req, res, next) => {
    console.log(req.body.username)
    try{
        const [user] = await db.findBy({username: req.body.username})
        console.log(user)
        if(user){
            next({status: 422, message: "username taken"})
        }
       
        else{
            req.user = user
            next()
        }

    }
    catch(err){
        next(err)
      }

}
const validateUserExsist = async(req, res, next) => {
    console.log(req.body.username)
    try{
        const [user] = await db.findBy({username: req.body.username})
        console.log(user)
        if(!user){
            next({status: 422, message: "Invalid credentials"})
        }
       
        else{
            req.user = user
            next()
        }

    }
    catch(err){
        next(err)
      }

}

const checkBodyValidation = (req,res,next)=>{
    if(!req.body.username || !req.body.password){
        next({status: 422, message: "username and password required"})
    }else{next()}

}
module.exports ={
    checkUsernameExists,
    checkBodyValidation,
    validateUserExsist
}