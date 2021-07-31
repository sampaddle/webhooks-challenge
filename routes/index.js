var app = require('express');
var router = app.Router();
const serial = require("generate-serial-key");
const crypto = require('crypto');
const Serialize = require('php-serialize');
const bodyParser = require("body-parser");
const { resolveInclude } = require('ejs');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.post('/hello', function(req, res) {

  if (validateWebhook(req.body)) {
    console.log('WEBHOOK_VERIFIED');
    const serial_no = serial.generate();
    console.log(serial_no);
    res.send('I can send anything I want back');
  } else {
    res.sendStatus(403);
    console.log('WEBHOOK_NOT_VERIFIED')
  }

// const serial_no = serial.generate();
// console.log(serial_no);
// console.log(req.body);
// res.send('I can send anything I want back');
})

router.get('/thanks', function (req, res) {
  res.render('thanks');
})

// Public key from your paddle dashboard
const pubKey = `-----BEGIN PUBLIC KEY-----

-----END PUBLIC KEY-----`

function ksort(obj){
  const keys = Object.keys(obj).sort();
  let sortedObj = {};
  for (let i in keys) {
    sortedObj[keys[i]] = obj[keys[i]];
  }
  return sortedObj;
}

function validateWebhook(jsonObj) {
  // Grab p_signature
  const mySig = Buffer.from(jsonObj.p_signature, 'base64');
  // Remove p_signature from object - not included in array of fields used in verification.
  delete jsonObj.p_signature;
  // Need to sort array by key in ascending order
  jsonObj = ksort(jsonObj);
  for (let property in jsonObj) {
      if (jsonObj.hasOwnProperty(property) && (typeof jsonObj[property]) !== "string") {
          if (Array.isArray(jsonObj[property])) { // is it an array
              jsonObj[property] = jsonObj[property].toString();
          } else { //if its not an array and not a string, then it is a JSON obj
              jsonObj[property] = JSON.stringify(jsonObj[property]);
          }
      }
  }
  // Serialise remaining fields of jsonObj
  const serialized = Serialize.serialize(jsonObj);
  // verify the serialized array against the signature using SHA1 with your public key.
  const verifier = crypto.createVerify('sha1');
  verifier.update(serialized);
  verifier.end();

  const verification = verifier.verify(pubKey, mySig);
  // Used in response if statement
  return verification;
}

module.exports = router;
