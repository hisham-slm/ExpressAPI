const mongoose = require('mongoose')
const userSchema = new mongoose.Schema({
    username : {
        type : String,
        require : true
    },
    password : {
        type : String,
        require : true
    },
    refreshToken : {
        type : String,
        require : true,
        default : ''
    }
})

module.exports = mongoose.model('user_auth' , userSchema)