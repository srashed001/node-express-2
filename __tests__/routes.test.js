// Set ENV VAR to test before we load anything, so our app's config will use
// testing settings

process.env.NODE_ENV = "test";

const app = require("../app");
const request = require("supertest");
const db = require("../db");
const bcrypt = require("bcrypt");
const createToken = require("../helpers/createToken");
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");

// tokens for our sample users
const tokens = {};

/** before each test, insert u1, u2, and u3  [u3 is admin] */

beforeEach(async function () {
  async function _pwd(password) {
    return await bcrypt.hash(password, 1);
  }

  let sampleUsers = [
    ["u1", "fn1", "ln1", "email1", "phone1", await _pwd("pwd1"), false],
    ["u2", "fn2", "ln2", "email2", "phone2", await _pwd("pwd2"), false],
    ["u3", "fn3", "ln3", "email3", "phone3", await _pwd("pwd3"), true],
  ];

  for (let user of sampleUsers) {
    await db.query(
      `INSERT INTO users VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      user
    );
    tokens[user[0]] = createToken(user[0], user[6]);
  }
});

describe("POST /auth/register", function () {
  test("should allow a user to register in", async function () {
    const response = await request(app).post("/auth/register").send({
      username: "new_user",
      password: "new_password",
      first_name: "new_first",
      last_name: "new_last",
      email: "new@newuser.com",
      phone: "1233211221",
    });
    expect(response.statusCode).toBe(201);
    expect(response.body).toEqual({ _token: expect.any(String) });

    let { username, admin } = jwt.verify(response.body._token, SECRET_KEY);
    expect(username).toBe("new_user");
    expect(admin).toBe(false);

    // *******************************************************************
    // TESTS BUG 6
    const authResp = await request(app).get('/users').send(response.body);
    expect(authResp.statusCode).toBe(200);
  });

  test("should not allow a user to register with an existing username", async function () {
    const response = await request(app).post("/auth/register").send({
      username: "u1",
      password: "pwd1",
      first_name: "new_first",
      last_name: "new_last",
      email: "new@newuser.com",
      phone: "1233211221",
    });
    expect(response.statusCode).toBe(400);
    expect(response.body).toEqual({
      status: 400,
      message: `There already exists a user with username 'u1'`,
    });
  });
  // *****************************************************************************************
  // TEST BUG #3
  test("should not allow a user to register with missing information: No last name", async function () {
    const response = await request(app).post("/auth/register").send({
      username: "u1",
      password: "pwd1",
      first_name: "new_first",
      email: "new@newuser.com",
      phone: "1233211221",
    });
    expect(response.statusCode).toBe(400);
  });

  // TEST BUG #3
  test("should not allow a user to register with invalid information", async function () {
    const response = await request(app).post("/auth/register").send({
      username: "u1",
      password: "pwd1",
      first_name: "new_first",
      last_name: "new_last",
      favorite_color: "purple",
      email: "new@newuser.com",
      phone: "1233211221",
    });
    expect(response.statusCode).toBe(400);
  });
});

describe("POST /auth/login", function () {
  test("should allow a correct username/password to log in", async function () {
    const response = await request(app).post("/auth/login").send({
      username: "u1",
      password: "pwd1",
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toEqual({ _token: expect.any(String) });

    let { username, admin } = jwt.verify(response.body._token, SECRET_KEY);
    expect(username).toBe("u1");
    expect(admin).toBe(false);
    // *******************************************************************
    // TESTS BUG 6
    const authResp = await request(app).get('/users').send(response.body);
    expect(authResp.statusCode).toBe(200)
  });
  // *************************************************************************
  // TEST BUG #4
  test("should not allow a NO username/password to log in", async function () {
    const response = await request(app).post("/auth/login").send({
      password: "pwd1",
    });
    expect(response.statusCode).toBe(400);
  });

  // TEST BUG #4
  test("should not allow a username/NO password to log in", async function () {
    const response = await request(app).post("/auth/login").send({
      username: "u1",
    });
    expect(response.statusCode).toBe(400);
  });

  // TEST BUG #4
  test("should not allow a NO username/NO password to log in", async function () {
    const response = await request(app).post("/auth/login");
    expect(response.statusCode).toBe(400);
  });
});

describe("GET /users", function () {
  test("should deny access if no token provided", async function () {
    const response = await request(app).get("/users");
    expect(response.statusCode).toBe(401);
  });
});

describe("GET /users", function () {
  // **************************************************************************
  // TESTS BUG #1
  test("should deny access if fake token provided", async function () {
    // payload contains same information as 'u1' however it is not signed
    const badActorToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImJhZF9hY3RvciIsImFkbWluIjp0cnVlLCJpYXQiOjE2NDEyNDEyMjN9`;
    // payload information is the same in both; however tokens[0] has been signed
    expect(jwt.decode(badActorToken)).toEqual(jwt.decode(tokens[0]));

    const response = await request(app).get(`/users?_token=${badActorToken}`);
    expect(response.statusCode).toBe(401);
  });
// ****************************************************************************************
// TESTS BUG #5
  test("should list all users", async function () {
    const response = await request(app)
      .get("/users")
      .send({ _token: tokens.u1 });
    expect(response.statusCode).toBe(200);
    expect(response.body.users.length).toBe(3);
    // TESTS BUG #5
    expect(response.body.users[0]).toEqual({
      username: 'u1',
      first_name: 'fn1',
      last_name: 'ln1'
    })
  });
});

describe("GET /users/[username]", function () {
  test("should deny access if no token provided", async function () {
    const response = await request(app).get("/users/u1");
    expect(response.statusCode).toBe(401);
  });

  test("should return data on u1", async function () {
    const response = await request(app)
      .get("/users/u1")
      .send({ _token: tokens.u1 });
    expect(response.statusCode).toBe(200);
    expect(response.body.user).toEqual({
      username: "u1",
      first_name: "fn1",
      last_name: "ln1",
      email: "email1",
      phone: "phone1",
    });
  });
});

describe("PATCH /users/[username]", function () {
  test("should deny access if no token provided", async function () {
    const response = await request(app).patch("/users/u1");
    expect(response.statusCode).toBe(401);
  });

  test("should deny access if not admin/right user", async function () {
    const response = await request(app)
      .patch("/users/u1")
      .send({ _token: tokens.u2 }); // wrong user!
    expect(response.statusCode).toBe(401);
  });

  test("should patch data if admin", async function () {
    const response = await request(app)
      .patch("/users/u1")
      .send({ _token: tokens.u3, first_name: "new-fn1" }); // u3 is admin
    expect(response.statusCode).toBe(200);
    expect(response.body.user).toEqual({
      username: "u1",
      first_name: "new-fn1",
      last_name: "ln1",
      email: "email1",
      phone: "phone1",
      admin: false,
      password: expect.any(String),
    });
  });
  // **************************************************************************************
  // TEST BUG #2
  test("should patch data if not admin BUT right user", async function () {
    const response = await request(app)
      .patch("/users/u1")
      .send({ _token: tokens.u1, first_name: "new-fn1" }); // u3 is admin
    expect(response.statusCode).toBe(200);
    expect(response.body.user).toEqual({
      username: "u1",
      first_name: "new-fn1",
      last_name: "ln1",
      email: "email1",
      phone: "phone1",
      admin: false,
      password: expect.any(String),
    });
  });

  // TEST BUG #2
  test("should disallow patching not-allowed-fields", async function () {
    const response = await request(app)
      .patch("/users/u1")
      .send({ _token: tokens.u1, admin: true });
    // TEST BUG #2 => SHOULD RETURN 400 BAD REQ, NOT 401 UNATHORIZED
    expect(response.statusCode).toBe(400);
  });

  test("should return 404 if cannot find", async function () {
    const response = await request(app)
      .patch("/users/not-a-user")
      .send({ _token: tokens.u3, first_name: "new-fn" }); // u3 is admin
    expect(response.statusCode).toBe(404);
  });
});

describe("DELETE /users/[username]", function () {
  test("should deny access if no token provided", async function () {
    const response = await request(app).delete("/users/u1");
    expect(response.statusCode).toBe(401);
  });

  test("should deny access if not admin", async function () {
    const response = await request(app)
      .delete("/users/u1")
      .send({ _token: tokens.u1 });
    expect(response.statusCode).toBe(401);
  });

  test("should allow if admin", async function () {
    const response = await request(app)
      .delete("/users/u1")
      .send({ _token: tokens.u3 }); // u3 is admin
    expect(response.statusCode).toBe(200);
    expect(response.body).toEqual({ message: "deleted" });
  });
});

afterEach(async function () {
  await db.query("DELETE FROM users");
});

afterAll(function () {
  db.end();
});
