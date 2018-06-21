'use strict';
const express = require('express'),
    app = express(),
    async = require('async'),
    logger = require('tracer').colorConsole(),
    _ = require('lodash'),
    mysql = require('mysql'),
    bodyParser = require('body-parser'),
    passport = require('passport'),
    cors = require('cors'),
    config = require('./config/config.js'),
    jwt = require('jsonwebtoken'),
    fs = require('file-system'),
    morgan = require('morgan'),
    login = require('./controllers/login.js');
    var controller /*= require('./controllers/controller.js')*/,
    _initialEtherAmount = "0.011",
    etherValueInWei = 1000000000000000000,
    db_connection = require('./config/dbconnection.js');
// app.listen(config.port);
app.use(express.static('../angular/PROJECT-NAME/dist'));
var server = app.listen(config.port);
var io = require('socket.io')(server);
app.use(cors());   
var expressValidator = require('express-validator');
app.use(expressValidator())
// app.use(cors({credentials: true, origin: 'http://localhost:7777'}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(morgan('common', {stream: fs.createWriteStream('./access.log', {flags: 'a'})}))
app.use(morgan('dev'));
app.use('/login',login);

// app.use('/', (req, res, next)=>{
//     const user = req.body.user || req.params.user || req.query.user || req.headers.user;
//     const token = req.body.token || req.params.token || req.query.password || req.headers.token;
//     async.waterfall([
//         function(callback){
//             var sql = 'SELECT * FROM login_info WHERE ?';
//             db_connection.query(sql,{user: user},callback);
//         },
//         function(doc, fields, callback){
//             if(doc.length){
//                 jwt.verify(token, doc[0].secret, callback);
//             } else {
//                 res.json({success: false, msg: 'Invalid user'});
//             }
            
//         }
//     ], (err, doc)=>{
//         if(doc && doc.user === user){
//             next();
//         } else {
//             res.json({success: false, msg: 'Invalid token'});
//         }
//     })
    
// })


// console.log('Server running on port number '+ config.port);
// const GoogleOAuth2Strategy = require('passport-google-auth').Strategy;
// const FacebookStrategy = require('passport-facebook').Strategy;
// passport.use(new GoogleOAuth2Strategy({
//     clientId: '677212888976-p8o546slmbpq05opt39ibkvhqs44hnbr.apps.googleusercontent.com',
//     clientSecret: 'cgXmneH_E2kRzPy-JweHEYhk',
//     callbackURL: 'https://ezchat.auth0.com'
//   },
//   function(accessToken, refreshToken, profile, done) {
//    console.log(accessToken);
//    console.log(refreshToken);
//    console.log(profile);
//    console.log(done);
//   }
// ));
  
// passport.use(new FacebookStrategy({
//     clientID: '677212888976-p8o546slmbpq05opt39ibkvhqs44hnbr.apps.googleusercontent.com',
//     clientSecret: 'cgXmneH_E2kRzPy-JweHEYhk',
//     callbackURL: 'https://ezchat.auth0.com',
//     profileFields:['id', 'displayName', 'photos', 'email']
//     }, function(accessToken, refreshToken, profile, done) {
//         console.log('helllooôœ');
//         console.log(profile);
//         // var me = new user({
//         //     email:profile.emails[0].value,
//         //     name:profile.displayName
//         // });

//         // /* save if new */
//         // user.findOne({email:me.email}, function(err, u) {
//         //     if(!u) {
//         //         me.save(function(err, me) {
//         //             if(err) return done(err);
//         //             done(null,me);
//         //         });
//         //     } else {
//         //         console.log(u);
//         //         done(null, u);
//         //     }
//         // });
//   }
// ));

// passport.serializeUser(function(user, done) {
//     console.log('user');
//     console.log(user);
//     done(null, user._id);
// });

// passport.deserializeUser(function(id, done) {
//     // user.findById(id, function(err, user) {
//     //     done(err, user);
//     // });
//     console.log(id);
//     console.log('hellllllllllllllllllllllllo');
// });

// // app.get('/auth/facebook', passport.authenticate('facebook', {scope:"email"}));
// app.get('/auth/facebook',
// passport.authenticate('facebook'),
// function(req, res){
//     console.log(req);
// });
// app.get('/auth/facebook/callback', passport.authenticate('facebook', 
// { successRedirect: '/', failureRedirect: '/login' }));


io.on('connection', function(socket) {
    console.log('connected');
    socket.on('clientEvent', function(data) {
       console.log(data);
    });
    app.use('/get', controller);
    
});

 var send_data = function(data){
     console.log(data);
    io.emit('new-message', data);
 }

 controller = require('./controllers/controller.js');
 app.use('/get', controller);
// io.emit('connection', io);

module.exports = {
    send_data: send_data 
}

const passportGoogle = require('passport-google-oauth');

const passportConfig = {
  clientID: '598902743876-go1guulac1hqa7tea5dqor44bt6fre1d.apps.googleusercontent.com',
  clientSecret: /*'E-0jCmg6JtsUonUJ9FfLcZBj'*/ 'adddd',
  callbackURL: 'http://localhost:7777/chat'
};

if (passportConfig.clientID) {
  passport.use(new passportGoogle.OAuth2Strategy(passportConfig, function (request, accessToken, refreshToken, profile, done) {
      console.log('-----------------------------------------------------------------------------------------------------------');
      console.log(profile);
      console.log('-----------------------------------------------------------------------------------------------------------');
    // // See if this user already exists
    // let user = users.getUserByExternalId('google', profile.id);
    // if (!user) {
    //   // They don't, so register them
    //   user = users.createUser(profile.displayName, 'google', profile.id);
    // }
    // return done(null, user);
  }));
}
const LocalStrategy = require('passport-local').Strategy;
// passport.use('google', new LocalStrategy({
//   // by default, local strategy uses username and password, we will override with email
//   usernameField : 'email',
//   passwordField : 'password',
//   passReqToCallback : true // allows us to pass back the entire request to the callback
// },
// function(req, email, password, done) {
//   console.log(email);
//   console.log(password);
//   console.log(done);
// }))
app.get('/api/authentication/google/start',
passport.authenticate('google', { session: false, scope: ['openid', 'profile', 'email'] }));
app.get('/api/authentication/google/redirect',
passport.authenticate('google', { session: false }),
generateUserToken);

function generateUserToken(req, res) {
    console.log('i am calling');
    const accessToken = token.generateAccessToken(req.user.id);
    res.render('authenticate.html/', {
      token: accessToken
    });
}



var expressSession = require('express-session');
app.use(expressSession({secret: 'E-0jCmg6JtsUonUJ9FfLcZBj'}));
app.use(passport.initialize());
app.use(passport.session());


passport.serializeUser(function(user, done) {
    done(null, user._id);
});
   
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

  passport.use('signupqqqq', new LocalStrategy({
    passReqToCallback : true
  },
  function(req, username, password, done) {
    findOrCreateUser = function(){
      // find a user in Mongo with provided username
      User.findOne({'username':username},function(err, user) {
        // In case of any error return
        
          var newUser = new User();
          // set the user's local credentials
          newUser.username = username;
          newUser.password = createHash(password);
          newUser.email = req.param('email');
          newUser.firstName = req.param('firstName');
          newUser.lastName = req.param('lastName');
          console.log(newUser);
        })
    };
     
    // Delay the execution of findOrCreateUser and execute 
    // the method in the next tick of the event loop
    process.nextTick(findOrCreateUser);
  })
);



var GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.use(new GoogleStrategy({
    // clientID: GOOGLE_CLIENT_ID,
    // clientSecret: GOOGLE_CLIENT_SECRET,
    // callbackURL: "http://www.example.com/auth/google/callback"

    clientID: '598902743876-go1guulac1hqa7tea5dqor44bt6fre1d.apps.googleusercontent.com',
    clientSecret: /*'E-0jCmg6JtsUonUJ9FfLcZBj'*/ 'adddd',
    callbackURL: 'http://localhost:7777/chat'
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get('/auth/google',
passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/callback', 
passport.authenticate('google', { failureRedirect: '/login' }),
function(req, res) {
  // Successful authentication, redirect home.
  res.redirect('/');
});



app.post('/hello', (req, res)=>{
  req.checkBody('uUid', 'uUid is required').notEmpty();
  req.checkBody('sessionId', 'sessionId is required').notEmpty();
  //validation check for errors
  req.asyncValidationErrors().then(function () {
  }).catch((err)=>{
    res.json(err);
  })
})


// get and config the module
var Payments = require( "node-payments" );
// inject and reuse a existing express
var paymentConfig = { express: app, paymentStore: new Payments.RedisHashStore() }
var pymts = new Payments( paymentConfig );
 

 






/* 


key id : 'rzp_test_X4tuLIdmm2zXtU',
key secret : '5O7Ebu9nk7qO5MV9ll0cVUoY'




*/


const Razorpay = require('razorpay');

const rzp = new Razorpay({
  key_id: 'rzp_test_X4tuLIdmm2zXtU', // your `KEY_ID`
  key_secret: '5O7Ebu9nk7qO5MV9ll0cVUoY' // your `KEY_SECRET`
})


// rzp.payments.all({
//   from: 'Aug 25, 2016',
//   to: 'Aug 30, 2018'
// }).then((data) => {
//   console.log(data)
// }).catch((error) => {
//   console.error(error)
// })



// rzp.transfers.create({
//   account: 'ezchat',
//   amount: 100,
//   currency: 'INR'
// }).then((data) => {
//   console.log(data)
// }).catch((error) => {
//   console.error(error)
// })


// rzp.transfers.create({
//   account: 'acc_A3juFHz3ijwk3q',
//   amount: 100,
//   currency: 'INR'
// }).then((data) => {
//    console.log(data)
// }).catch((error) => {
//    console.error(error);
// })

// var razorid = 'A3JuFHz3ijwk3q';
// var amount = 2000;
// rzp.payments.capture(razorid, amount).then((data) => {
//   console.log('Payment successful');
//   // res.status(200);
// }).catch((error) => {
//   console.log('Payment un-successful' + error);
//   console.log(error);
//   // res.status(400);
// })


var BigNumber = require('bignumber.js');
var Web3 = require('web3');
var net = require('net');
var Web3EthPersonal = require('web3-eth-personal');
var Web3EthContract = require('web3-eth-contract');
var web3 = new Web3(Web3.givenProvider || "ws://localhost:8545");

// console.log(web3);

web3 = new Web3('/Users/ramarao.g/Library/Ethereum/geth.ipc', net);
var personal = new Web3EthPersonal('/Users/ramarao.g/Library/Ethereum/geth.ipc', net);
Web3EthContract.setProvider("ws://localhost:8545");
// web3.eth.getBalance("0x1647644e6f446e1d873b0412ecec4e167a1b471b").then((bal)=>{
//   console.log('---------------------------------');
//   console.log(bal);
//   console.log('---------------------------------');
// }).catch((err)=>{
//   console.log(err);
// })
// web3.eth.getBlockTransactionCount(1, 0).then((res)=>{
//   console.log(res);
// }).catch((err)=>{
//   console.log(err);
// });


var sampleContractABI = [{
  "constant": true,
  "inputs": [],
  "name": "name",
  "outputs": [{
      "name": "",
      "type": "string"
  }],
  "payable": false,
  "stateMutability": "view",
  "type": "function"
}, {
  "constant": false,
  "inputs": [{
      "name": "_spender",
      "type": "address"
  }, {
      "name": "_value",
      "type": "uint256"
  }],
  "name": "approve",
  "outputs": [{
      "name": "success",
      "type": "bool"
  }],
  "payable": false,
  "stateMutability": "nonpayable",
  "type": "function"
}, {
  "constant": true,
  "inputs": [],
  "name": "totalSupply",
  "outputs": [{
      "name": "",
      "type": "uint256"
  }],
  "payable": false,
  "stateMutability": "view",
  "type": "function"
}, {
  "constant": false,
  "inputs": [{
      "name": "_from",
      "type": "address"
  }, {
      "name": "_to",
      "type": "address"
  }, {
      "name": "_value",
      "type": "uint256"
  }],
  "name": "transferFrom",
  "outputs": [{
      "name": "success",
      "type": "bool"
  }],
  "payable": false,
  "stateMutability": "nonpayable",
  "type": "function"
}, {
  "constant": true,
  "inputs": [],
  "name": "decimals",
  "outputs": [{
      "name": "",
      "type": "uint8"
  }],
  "payable": false,
  "stateMutability": "view",
  "type": "function"
}, {
  "constant": true,
  "inputs": [],
  "name": "version",
  "outputs": [{
      "name": "",
      "type": "string"
  }],
  "payable": false,
  "stateMutability": "view",
  "type": "function"
}, {
  "constant": true,
  "inputs": [{
      "name": "_owner",
      "type": "address"
  }],
  "name": "balanceOf",
  "outputs": [{
      "name": "balance",
      "type": "uint256"
  }],
  "payable": false,
  "stateMutability": "view",
  "type": "function"
}, {
  "constant": true,
  "inputs": [],
  "name": "symbol",
  "outputs": [{
      "name": "",
      "type": "string"
  }],
  "payable": false,
  "stateMutability": "view",
  "type": "function"
}, {
  "constant": false,
  "inputs": [{
      "name": "_to",
      "type": "address"
  }, {
      "name": "_value",
      "type": "uint256"
  }],
  "name": "transfer",
  "outputs": [{
      "name": "success",
      "type": "bool"
  }],
  "payable": false,
  "stateMutability": "nonpayable",
  "type": "function"
}, {
  "constant": false,
  "inputs": [{
      "name": "_spender",
      "type": "address"
  }, {
      "name": "_value",
      "type": "uint256"
  }, {
      "name": "_extraData",
      "type": "bytes"
  }],
  "name": "approveAndCall",
  "outputs": [{
      "name": "success",
      "type": "bool"
  }],
  "payable": false,
  "stateMutability": "nonpayable",
  "type": "function"
}, {
  "constant": true,
  "inputs": [{
      "name": "_owner",
      "type": "address"
  }, {
      "name": "_spender",
      "type": "address"
  }],
  "name": "allowance",
  "outputs": [{
      "name": "remaining",
      "type": "uint256"
  }],
  "payable": false,
  "stateMutability": "view",
  "type": "function"
}, {
  "inputs": [{
      "name": "_initialAmount",
      "type": "uint256"
  }, {
      "name": "_tokenName",
      "type": "string"
  }, {
      "name": "_decimalUnits",
      "type": "uint8"
  }, {
      "name": "_tokenSymbol",
      "type": "string"
  }],
  "payable": false,
  "stateMutability": "nonpayable",
  "type": "constructor"
}, {
  "payable": false,
  "stateMutability": "nonpayable",
  "type": "fallback"
}, {
  "anonymous": false,
  "inputs": [{
      "indexed": true,
      "name": "_from",
      "type": "address"
  }, {
      "indexed": true,
      "name": "_to",
      "type": "address"
  }, {
      "indexed": false,
      "name": "_value",
      "type": "uint256"
  }],
  "name": "Transfer",
  "type": "event"
}, {
  "anonymous": false,
  "inputs": [{
      "indexed": true,
      "name": "_owner",
      "type": "address"
  }, {
      "indexed": true,
      "name": "_spender",
      "type": "address"
  }, {
      "indexed": false,
      "name": "_value",
      "type": "uint256"
  }],
  "name": "Approval",
  "type": "event"
}];
var contract = new Web3EthContract(sampleContractABI, '0x5cb023C894D7838Ee7C0eE43AFD8D10D75Cd89bd');
// web3.eth.getGasPrice(function (err, gasPrice) {
//   console.log('gasPrice-----------------------------');
//   console.log(gasPrice);
//   console.log('-------------------------------------');
// });




app.get('/get/contract/:address', (req, res)=>{
  contract.methods.balanceOf(req.params.address).call({
    from: req.params.address
  }, function (error, resultBalance) {
    if(!error){
      res.json({success: true, msg: resultBalance});
    } else {
      console.log(error);
      res.json({success: false, msg: error});
    }
  });
})


// web3.eth.getTransaction("0x49218cffef59de96a4fbbf4a7b3b1c31f09b2406").then((res)=>{
//   console.log(res);
// });
// console.log(web3.eth.accounts);
// console.log(web3.eth.getBalance);
// console.log(web3.eth.getBalance("0x1647644e6f446e1d873b0412ecec4e167a1b471b"), (res, err)=>{
//   if(err){
//     console.log(err);
//   } else {
//     console.log(res);
//   }
// });
// console.log(web3.getBalance("0x1647644e6f446e1d873b0412ecec4e167a1b471b"));
// web3.eth.sendTransaction({from: '0x49218cffef59de96a4fbbf4a7b3b1c31f09b2406', data: '1'})
// .once('transactionHash', function(hash){
//   console.log('hash------------------------------');
//   console.log(hash);
//   console.log('------------------------------hash');
// })
// .once('receipt', function(receipt){
//   console.log('receipt------------------------------');
//   console.log(receipt);
//   console.log('------------------------------receipt');
// })
// .on('confirmation', function(confNumber, receipt){ 
//   console.log('confirmation------------------------------');
//   console.log(confirmation);
//   console.log('------------------------------confirmation');
// })
// .on('error', function(error){
//   console.log('error------------------------------');
//   console.log(error);
//   console.log('------------------------------error');
// })
// .then(function(receipt){
//   console.log('receipt------------------------------');
//   consoe.log(receipt);
//   console.log('------------------------------receipt');
// });


// var web3 = new Web3(new Web3.providers.HttpProvider('http://localhost:8545'));
// web3 = new Web3('/Users/myuser/Library/Ethereum/geth.ipc', net);
// web3.eth.personal.newAccount('1234').then((res)=>{
//   console.log(res);
// }).catch((err)=>{
//   console.log(err);
// })
// console.log(web3.eth.personal);
app.get('/wallet', (req, res)=>{
  var wallet = web3.eth.accounts.wallet;
  console.log(wallet);
  res.json(true);
})

app.get('/add/wallet', (req, res)=>{
  var wallet = web3.eth.accounts.wallet.add({
    privateKey: '0x4708699ea9a71e3cea290f3c0d9cb607501c7cb7dc0e9d1e947b6ad50ca5e694',
    address: '0xfa4dE3140f4473807DB11dCAEBad523966181c82'
  });
  res.json(wallet);
})


app.get('/transaction', (req, res)=>{
  web3.eth.accounts.signTransaction({
    to: '0x85f3c81738E08cB4Ae88a19F68442698a64883ea',
    value: '1000000000',
    gas: 2000000,
    gasPrice: '234567897654321',
    nonce: 0,
    chainId: 1
  }, '0x4708699ea9a71e3cea290f3c0d9cb607501c7cb7dc0e9d1e947b6ad50ca5e694')
  .then((doc)=>{
    res.json(doc)
  }).catch((err)=>{
    res.json(err);
  });
})

app.get('/get/amount', (req, res)=>{
  web3.eth.getBalance("0x85f3c81738E08cB4Ae88a19F68442698a64883ea").then((bal)=>{
    res.json(bal);
  }).catch((err)=>{
    res.json(err);
  })
})


app.get('/remove/wallet', (req, res)=>{
  var status = web3.eth.accounts.wallet.remove('0x30727883ba34e569d7693bfeafaae7939841a9b835238065631e8d793052ff68');
  res.json(status);
})

app.get('/privatekey_to/account', (req, res)=>{
  var result = web3.eth.accounts.privateKeyToAccount('0x30727883ba34e569d7693bfeafaae7939841a9b835238065631e8d793052ff68');
  res.json(result);
})

app.get('/recover', (req, res)=>{
  var results = web3.eth.accounts.recover({
    messageHash: '0x53cb339abab1d29913b03da3c591ac4ac01ebf73ecad4231a3a2aae40861f971',
    v: '0x26',
    r: '0xecd110441dc2ecaf25fd724687af57cfc55b0a36a20bc0a3c5a9eef7cf02df00',
    s: '0x4b30d8a803d37ff99313a135afe01eaf88ff98e5776c066c4cf15177dc7ade8a'
  })
  res.json(results);
})
app.get('/hash_message/:msg', (req, res)=>{
  console.log(req.params.msg);
  var result = web3.eth.accounts.hashMessage(req.params.msg);
  res.json(result);
})



app.post('/post/transaction', (req, res)=>{
  console.log(req.body);
  check_initial_balance(req.body.from_account).then((initial_balance)=>{
    if(initial_balance){
      personal.unlockAccount(req.body.from_account, req.body.pwd).then(function (result) {
        web3.eth.estimateGas({to: req.body.to_account, value: web3.utils.toWei(_initialEtherAmount, "ether")}, (err, estimate_gase)=>{
          estimate_gase = parseInt(estimate_gase);
          estimate_gase += ((estimate_gase/100)*10);
          web3.eth.getGasPrice((err, gase_price)=>{
            gase_price = parseInt(gase_price);
            gase_price += ((gase_price/100)*5);
            web3.eth.sendTransaction({
              from: req.body.from_account,
              to: req.body.to_account,
              value: req.body.value,
              gas:estimate_gase,
              gasePrice:gase_price
            }).then(function (receipt) {
              web3.eth.getBalance(req.body.to_account).then(function (result) {
                  console.log(result);
                  res.json({success: true, to_account_bal: result, transaction: receipt});
              }).catch(function (error) {
                  console.log("Error", error);
                  res.json({success: false, err: err});
              });
            }).catch(function (error) { 
              console.log("Error is:-", error); 
              res.json({success: false, err: error});
            })
          })
        })
        
      }).catch(function (error) { 
        console.log("Authentication Error is:-", error); 
        res.json({success: false, err: error});
    
      })
    } else {
      res.json({success: false, msg:'Account has no initial amount'});
    }
    
  }).catch((err)=>{
    res.json({success: false, msg: err});
  })
  
})


app.get('/get/accounts', (req, res)=>{
  console.log('i am calling');
  web3.eth.getAccounts().then((response)=>{
    res.json({success: true, accounts: response});
  }).catch((err)=>{
    console.log(err);
    res.json({success: false, error: err});
  })
})

app.get('/get/balance/:account', (req, res)=>{
  web3.eth.getBalance(req.params.account).then((response)=>{
    res.json({success: true, balance: response});
  }).catch((err)=>{
    res.json({success: false, error: err});
  })
})

app.get('/transaction/recovery', (req, res)=>{

})

app.post('/get/estimategase', (req, res)=>{
  web3.eth.estimateGas({
    to: req.body.sender_address,
    value: web3.utils.toWei(req.body._initialEtherAmount, "ether")
  }).then(function (gasEstimate) {
    console.log('response');
    res.json({success: true, msg: gasEstimate})
  }).catch((err)=>{
    console.log('error');
    res.json({success: false, msg: err});
  })
})



app.post('/create/account', (req, res)=>{
  personal.newAccount(req.body.pwd, (err, account)=>{
    if(!err){
      res.json({success: true, msg:{account: account}});
    } else {
      res.json({success: false, msg: err});
    }
  })
})


app.get('/transaction/count/:address', (req, res)=>{
  web3.eth.getTransactionCount(req.params.address, (err, count)=>{
    if(!err){
      res.json({success: true, msg:{count: count}});
    } else {
      res.json({success: false, msg:{err: err}});
    }
  })
})

app.get('/get/transaction/:transaction_hash', (req, res)=>{
  web3.eth.getTransaction(req.params.transaction_hash, (err, trans)=>{
    if(!err){
      res.json({success: true, msg: {transaction: trans}});
    } else {
      res.json({success: false, msg:{err: err}});
    }
  })
})


app.get('/get/subscribe', (req, res)=>{
  web3.eth.subscribe('pendingTransactions', (err, results)=>{
    if(!err){
      res.json({success: true, msg: results});
    } else {
      res.json({success: false, msg: err});
    }
  })
})

app.get('/get/estimate_gas/:address', (req, res)=>{
  web3.eth.estimateGas({
    to: req.params.address,
    value: web3.utils.toWei(_initialEtherAmount, "ether")
  }, (err, result)=>{
    if(!err){
      res.json({success: true, msg: result});
    } else {
      res.json({success: false, msg: err});
    }
  })
})

app.get('/validate/:address', (req, res)=>{
  res.json(web3.utils.isAddress(req.params.address));
})

app.get('/get/block/:block_number', (req, res)=>{
  web3.eth.getBlock(req.params.block_number, function(error, result){
    if(!error){
      // console.log(result);
      res.json({success: true, msg: result});
    }
    else{
      // console.log(error);
      res.json({success: false, msg: error});
    }
        
  })
})



function check_initial_balance(address){
  return new Promise((resolve, reject)=>{
    web3.eth.getBalance(address, (err, balance)=>{
      if (!err) {
        console.log(balance / etherValueInWei);
        if(parseFloat(balance / etherValueInWei) >= parseFloat(_initialEtherAmount)) {
           // res.json({success: true, msg: 1});
           resolve(1);
        }else{
          resolve(0);
        }
      }else{
        reject(err);
      }
    })
  })
}



// get functions 



app.get('/get/web3/amount', (req, res)=>{
  web3.eth.watch({altered: web3.eth.coinbase}).changed(function(){
    web3.eth.balanceAt(web3.eth.coinbase).then((results)=>{
      res.json({success: true, res: results});
    })
  }).catch((err)=>{
    res.json({success: false, res: err});
  })
})










app.get('/*', function(req, res){
    // res.sendFile(__dirname+'../'+'/angular/PROJECT-NAME/dist/index.html');
    res.sendFile('index.html', { root: '../angular/PROJECT-NAME/dist/'});
});




// let Block = require('./block')
// let Transaction = require('./transaction')
// let Blockchain = require('./blockchain')

// // create genesis block
// let genesisBlock = new Block()
// let blockchain = new Blockchain(genesisBlock)

// // create a transaction
// let transaction = new Transaction('Mary','John',100)
// let block = blockchain.getNextBlock([transaction])
// blockchain.addBlock(block)

// let anotherTransaction = new Transaction("Azam","Jerry",10)
// let block1 = blockchain.getNextBlock([anotherTransaction,transaction])
// blockchain.addBlock(block1);
// console.log(blockchain)


// var obj = {a: 'A', b: 'B'};
// console.log(obj.toString());
// console.log(JSON.stringify(obj));
// // console.log(JSON.parse(obj));


// var result = web3.eth.sendTransaction({
//   from: 'cd2a3d9f938e13cd947ec05abc7fe734df8dd826', 
//   to:'0x03877F14C11e3703ad537a94818C7C3E04D7Fc33', 
//   value: 500, 
//   gasLimit: 21000, 
//   gasPrice: 18000000000
// })

// console.log(result);
// web3.eth.personal.unlockAccount('0x994c39db1db2f152f8824f773fb6636dc3f50e9b', 'pwd').then(function (result) {
//   console.log(result);
// web3.eth.sendTransaction({
//   from: '0x994c39db1db2f152f8824f773fb6636dc3f50e9b',
//   to: '0x8d6c1a3a387f45c4c3aeb9c28c212beee873bf69',
//   value: 500
// })
// .then(function (receipt) {
//   console.log('i am calling');
//   console.log(receipt);
// }).catch((err)=>{
//   console.log('err  '+err);
//   console.log('error calling');
// })
// })
// web3.eth.getAccounts().then(function(o) {
//   web3.eth.getBalance(o[0]).then((res)=>{
//     console.log(res);
//   })
// }).catch((err)=>{
//   console.log(err);
// }).catch((err)=>{
//   console.log('/////////');
//   console.log(err);
//   console.log('///////////');
// })

// web3.eth.getBalance("cd2a3d9f938e13cd947ec05abc7fe734df8dd826").then((res)=>{
//   console.log(res);
// });


// web3.eth.personal.unlockAccount(fromAccount, fromAccountPassword).then(function (result) {

//     web3.eth.sendTransaction({
//         from: fromAccount,
//         to: toAccount,
//         value: value
//     }).then(function (receipt) {
//         web3.eth.getBalance('' + toAccount + '').then(function (result) {
//             console.log(" Result in getbalance function", result);
//         }).catch(function (error) {
//             console.log("Error", error);
//         });

//     }).catch(function (error) { console.log("Error is:-", error); })
// }).catch(function (error) {
//     console.log(" Error is:-", error);
// });

// web3.eth.getBlock("latest").then((res)=>{
//   console.log(res);
// }).catch((err)=>{
//   console.log(err);
// })

// web3.eth.getAccounts().then((res)=>{
//   console.log(res);
// }).catch((err)=>{
//   console.log(err);
// })
