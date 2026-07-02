const joi = require('joi');

module.exports.registerSchema = joi.object({
    name: joi.string().required(),
    email: joi.string().email().required(),
    password: joi.string().min(8).required()
})


module.exports.loginSchema = joi.object({
    email: joi.string().email().required(),
    password: joi.string().required()
})