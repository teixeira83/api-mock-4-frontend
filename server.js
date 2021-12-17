const fs = require('fs')
const bodyParser = require('body-parser')
const jsonServer = require('json-server')
const jwt = require('jsonwebtoken')

const server = jsonServer.create()
const router = jsonServer.router('./database.json')
const userdb = JSON.parse(fs.readFileSync('./users.json', 'UTF-8'))

//faz com que o req.body aceite valores de qualquer tipo não somente strings
server.use(bodyParser.urlencoded({ extended: true }))
server.use(bodyParser.json())
server.use(jsonServer.defaults());

const SECRET_KEY = '123456789'

const expiresIn = '1h'

function createToken(payload){
  return jwt.sign(payload, SECRET_KEY, { expiresIn })
}

function verifyToken(token){
  return  jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ?  decode : err)
}

// realiza o check se o usuário existe na database
function isAuthenticated({ email, password }){
  return userdb.users.findIndex(user => user.email === email && user.password === password) !== -1
}

server.post('/auth/register', (req, res) => {
  console.log("register endpoint called; request body:");
  console.log(req.body);
  const {email, password} = req.body;

  if(isAuthenticated({email, password}) === true) {
    const status = 401;
    const message = 'Email and Password already exist';
    res.status(status).json({status, message});
    return
  }

  fs.readFile("./users.json", (err, data) => {  
      if (err) {
        const status = 401
        const message = err
        res.status(status).json({status, message})
        return
      };

      const listOfUsers = JSON.parse(data.toString());
      
      const greaterUserId = listOfUsers.users[listOfUsers.users.length-1].id;

      const newListOfUsers = [
        ...listOfUsers.users,
        {
          id: greaterUserId + 1, 
          email: email,
          password: password  
        }
      ];
      
      const writeData = fs.writeFile("./users.json", JSON.stringify({ users: newListOfUsers }) , (err, result) => {
          if (err) {
            const status = 401
            const message = err
            res.status(status).json({status, message})
            return
          }
      });
  });

  const newUserAccessToken = createToken({ email, password })
  
  console.log("Access Token:" + newUserAccessToken);
  
  res.status(200).json({ access_token: newUserAccessToken })
});

server.post('/auth', (req, res) => {
  console.log("login endpoint called; request body:");
  console.log(req.body);

  const { email, password } = req.body;

  if (isAuthenticated({ email, password }) === false) {
    const status = 401

    const message = 'Incorrect email or password'

    res.status(status).json({ status, message })

    return;
  }

  const accessToken = createToken({ email, password })

  console.log("Access Token:" + accessToken);

  res.status(200).json({ access_token: accessToken })
});

server.use(/^(?!\/auth).*$/,  (req, res, next) => {
  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    const status = 401
    const message = 'Error in authorization format'
    res.status(status).json({status, message})
    return
  }
  try {
    let verifyTokenResult;
     verifyTokenResult = verifyToken(req.headers.authorization.split(' ')[1]);

     if (verifyTokenResult instanceof Error) {
       const status = 401
       const message = 'Access token not provided'
       res.status(status).json({status, message})
       return
     }
     next()
  } catch (err) {
    const status = 401
    const message = 'Error access_token is revoked'
    res.status(status).json({status, message})
  }
});

server.get('/users', (req, res) => {
  fs.readFile("./users.json", (err, data) => {  
    if (err) {
      const status = 401
      const message = err
      res.status(status).json({ status, message })
      return
    };
    
    const users = JSON.parse(data.toString());


    const status = 200
    const listOfUsers = users.users
    return res.status(status).json({ status, users: listOfUsers })
  });
});

server.use(router)

server.listen(8000, () => {
  console.log('Running Fake API 4 FrontEnd')
})