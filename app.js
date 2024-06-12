require('dotenv').config()
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const express = require('express')
const User = require('./models/User')
const app = express()

app.use(express.json())

app.get('/user/:id', checkToken, async(req, res) => {
    const id = req.params.id
    const user = await User.findById(id, '-password')
    if(!user){
        return res.status(400).json({message: 'ATENÇÃO: Usuario não encontrado!'})
    }
    res.status(200).json({user})
})
function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if(!token){
        return res.status(401).json({message: 'ATENÇÃO: Acesso negado!'})
    }
    try{
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()
    }catch(error){
        res.status(400).json(error)
    }
}
app.post('/auth/register', async(req, res) => {
    const {name, email, password, confirmPassword} = req.body
    if(
        !name || 
        !email||
        !password ||
        !confirmPassword
    ){
        return res.status(400).json({message: 'ATENÇÃO: Todos os campos devem ser preenchidos!'})
    }
    if(password !== confirmPassword){
        return res.status(400).json({message: 'ATENÇÃO: As senhas não conferem!'})
    }
    const userExists = await User.findOne({email:email})
    if(userExists){
        return res.status(400).json({message: 'ATENÇÃO: Utilizar outro e-mail!'})
    }
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)
    const user = new User({
        name,
        email,
        password: passwordHash,
    })
    try{
        await user.save()
        return res.status(201).json({message: 'INFORMAÇÃO: Usuário criado com sucesso!'})

    }catch(error){
        res.status(500).json(error)
    }
})
app.post('/auth/login', async(req, res) => {
    const {email, password} = req.body
    const user = await User.findOne({email: email})
    const checkPassword = await bcrypt.compare(password, user.password)
    if(!email || !password){
        return res.status(400).json({message: 'ATENÇÃO: Usuario não encontrado!'})
    } else if(!user){
        return res.status(400).json({message: 'ATENÇÃO: Usuario não encontrado!'})
    } else if(!checkPassword){
        return res.status(400).json({message: 'ATENÇÃO: Senha invalida!'})
    }
    try{
        const secret = process.env.secret
        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        )
        res.status(200).json({message: "INFORMAÇÃO: Autenticação realizada com sucesso!", token})
    }catch(error){
        res.status(500).json(error)
    }
})
const dbUser = process.env.DB_USER
const dbPass = encodeURIComponent(process.env.DB_PASS)
mongoose.connect(
    `mongodb+srv://${dbUser}:${dbPass}@apicluster.fvlvnuc.mongodb.net/autenticacao?retryWrites=true&w=majority&appName=APICluster`
,).then(() => {
    app.listen(3000)
    console.log('Banco de Dados CONECTADO!')
}).catch((err) => console.log(err))