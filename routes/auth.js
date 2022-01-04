/** Auth-related routes. */

const User = require('../models/user');
const express = require('express');
const router = express.Router();
const createTokenForUser = require('../helpers/createToken');
const ExpressError = require("../helpers/expressError")
const jsonschema = require("jsonschema");
const userNewSchema = require("../schemas/userNew.json")
const userLoginSchema = require("../schemas/userLogin.json")


/** Register user; return token.
 *
 *  Accepts {username, first_name, last_name, email, phone, password}.
 *
 *  Returns {token: jwt-token-string}.
 *
 */
// ****************************************************************************************
// FIXES BUG #3
router.post('/register', async function(req, res, next) {
  try {
    // FIXES BUG #3
    const result = jsonschema.validate(req.body, userNewSchema);

    if (!result.valid) {
      let listOfErrors = result.errors.map(error => error.stack);
      let error = new ExpressError(listOfErrors, 400);
      return next(error);
    }

    const { username, password, first_name, last_name, email, phone } = req.body;
    let user = await User.register({username, password, first_name, last_name, email, phone});
    const token = createTokenForUser(username, user.admin);
    // ***************************************************************************************
    // FIXES BUG 6 
    return res.status(201).json({ _token: token });
  } catch (err) {
    return next(err);
  }
}); // end

/** Log in user; return token.
 *
 *  Accepts {username, password}.
 *
 *  Returns {token: jwt-token-string}.
 *
 *  If incorrect username/password given, should raise 401.
 *
 */
// **********************************************************************************************
// FIXES BUG #4
router.post('/login', async function(req, res, next) {
  try {
    // FIXES BUG 4 
    const result = jsonschema.validate(req.body, userLoginSchema);

    if (!result.valid) {
      let listOfErrors = result.errors.map(error => error.stack);
      let error = new ExpressError(listOfErrors, 400);
      return next(error);
    }

    const { username, password } = req.body;
    let user = User.authenticate(username, password);
    const token = createTokenForUser(username, user.admin);
      // ***************************************************************************************
    // FIXES BUG 6
    return res.json({ _token: token });
  } catch (err) {
    return next(err);
  }
}); // end

module.exports = router;
