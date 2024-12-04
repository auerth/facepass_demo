
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());


/**
 * Definitions
 * 
 * The vid is a unique identifier that identifies a verification process. It is used specifically for the verification of an individual ticket or access authorisation.
 * The sid refers to the entire session (e.g. a person going through the gate), while vid is specific to a single verification process (e.g. scanning a ticket).
 * 
 */

function authenticate(req, res, next) {
  const { appid, timestamp, reqid, sign } = req.headers;

  if (!appid || !timestamp || !reqid || !sign) {
    return res.status(401).json({ code: -1, msg: 'Authentication parameters missing' });
  }
  //This part must dynamically read the secretkey during authentication using the appid transferred
  const AppId = '75937e2e-9d6e-4927-b9c1-846423e10d06'; // Application ID for connecting to the AP, generator by event creating
  const SecretKey = '682dbceb21389a5417f50e17e16dfdf2'; // Secret Key for generating the signature, for an event - generate by event creating and search by Application ID

  const expectedSign = crypto
    .createHash('md5')
    .update(`${AppId}#${timestamp}#${reqid}#${SecretKey}`)
    .digest('hex')
    .toLowerCase();

  if (sign !== expectedSign) {
    return res.status(401).json({ code: -1, msg: 'Invalid signature' });
  }

  next();
}

app.post('/device/access/valid', authenticate, (req, res) => {
  const { sid, vid, voucherType, voucher, devNo } = req.body;

  if (!sid || !vid || !voucherType || !voucher || !devNo) {
    return res.status(400).json({ code: -1, msg: 'Missing required parameters' });
  }

  /**This ticket validation must be adapted.
  *
  * voucher is an unique string for the ticket
  *
  * voucherType is send by the gate. following values are possible
  * 1 -  QRCode
  * 2 -  Barcode
  * 3 -  RFID
  * 4 -  NFC
  * 
  * Perhaps  it is irrelevant for validation
  * */
  const isValid = voucherType === 1 && voucher === 'TicketQRcodeContent';


  const person = "Demo Client" //Name of the person who owns the ticket
  const ticketDescription = "Demo Ticket Type"; //Ticket description 
  const personCount = 1; // Number of people who can pass through the gate for the tickettype

  //vid and sid should be saved so that they can be associated with a ticket in the process /device/access/report

  res.json({
    code: isValid ? 0 : -1,
    data: {
      sid,
      vid,
      pass: isValid,
      code: isValid ? 0 : -1,
      msg: isValid ? 'ok' : 'invalid ticket',
      voucherType,
      voucher,
      voucherPerson: isValid ? person : null,
      voucherMsg: isValid ? ticketDescription : null,
      passesNum: isValid ? personCount : 0,
    },
  });
});

app.post('/device/access/report', authenticate, (req, res) => {
  const { sid, vid, devNo } = req.body;

  if (!sid || !vid || !devNo) {
    return res.status(400).json({ code: -1, msg: 'Missing required parameters' });
  }

  //The person from ticket validation has passed the gate, ticket should be defined as used here by vid and sid

  res.json({
    code: 0,
    data: {
      sid,
      vid,
    },
  });
});

const PORT = 3000; // Change the port if necessary

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
