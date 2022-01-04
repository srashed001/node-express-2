- BUG #1: jwt.decode does not verify token, it just translates payload. Correct method is jwt.verify

- BUG #2: 
    * remove requireAuth middleware, prevents right user from patching own data 
    * setup validation using jsonschema to prevent input of bad data 
    * included test for right user/not admin to make patch request to update their own data 
    * changed one test to test for 400 bad request instead of 401 unath

- BUG #2: 
    * remove requireAuth middleware, prevents right user from patching own data 
    * setup validation using jsonschema to prevent input of bad data 
    * included test for right user/not admin to make patch request to update their own data 
    * changed one test to test for 400 bad request instead of 401 unath

- BUG #3: 
    * setup validation using jsonschema to prevent input of missing/bad data 
    * test that user not allowed to register with missing field "last name"
    * test that error is thrown if user registers with invalid fields "favorite_color: purple"

- BUG #4: 
    * setup validation using jsonschema to prevent input of missing/bad data 
    * test that user not allowed to login without providing both username and password

- BUG #5: 
    * edited getAll method to provide only basic data as prescribed by the route 
    * tested GET "/users" route to ensure only basic data was being displayed

- BUG #6: 
    * auth routes for /register and /login were inaccurately setting the key for token object
    * changed from {token: token} and {_token, token}
    * authUser looks for _token property in req.body and req.query; NOT token
    * in tests for /register and /login - added code to show that response.body which includes data can successfully make requests to /user route that requires valid token 
        * requests were denied before token property was correctly changed 

