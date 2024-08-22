import Database from 'better-sqlite3';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import path from 'path';
import fs from 'fs';
import pino from 'pino';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';

const logger = pino();

// A small note on environment variables.
// An Environment variable is a variable that is set outside of the application and is used to configure the application.
// Now, depending on the shell (powershell, bash) you're using, the way to set environment variables is different.
// Using the 'cross-env' package allows you to set environment variables in a cross-platform way (usually Powershell is used on Windows and Bash (or zsh) on Unix-based systems).
// The point is that if you look at the package.json in the server directory, you'll see that we set the NODE_ENV variable to 'development' in the 'dev' script and to 'production' in the 'prod' script. (we also set some other ones, you'll see)
// This env (short for environment) variable is used to determine in which mode the application is running.
// We can use this to provide different configurations for different environments, see below.

// This is just a reference to the package.json, so you don't have to look there:
// "scripts": {
//   "dev": "cross-env NODE_ENV=development nodemon server/index.js | pino-pretty",
//   "prod": "cross-env NODE_ENV=production node server/index.js"
// },

// Also note the `process.env.VARIABLE_NAME`. This is how we access environment variables.

const ROOT_DIR = path.dirname(import.meta.dirname); // absolute path to the root directory of the project

// This is how we access the environment variables.
const IS_PROD = process.env.NODE_ENV === 'production';
const IS_DEV = process.env.NODE_ENV === 'development';

logger.info(`Running in ${IS_PROD ? 'production' : 'development'} mode`);

// We can also pass the port as an env variable. This is useful when deploying the app to change the port or some configuration without messing with the code itself.
const PORT = process.env.PORT || 3000;

// This ORIGIN is also be passed as an env variable. This will be useful when we deploy the frontend to a domain, and we need to specify the origin of the requests like: mywebsite.com.
// But if it's not defined, or we are in development mode we'll just default to allowing `http://localhost:5173` (where the client is).
// NOTE: If we defaulted to `*`, even for development reasons, we would still get CORS error in the browser when doing `credentials: 'include'` because the browser doesn't allow `*` with credentials.
//       So we have to specify a specific origin for it to work.
// If we are in production and we don't specify ORIGIN then we default to null and we'll error (see below).
const ORIGIN = process.env.ORIGIN || IS_DEV ? `http://localhost:5173` : null;
logger.info(`CORS: Allowed origin: ${ORIGIN}`);

// This is just some extra configuratio for the database name.
const DB_NAME = process.env.DB_NAME || 'database'; // db name without file extension, defaults to 'database'

// Absolute path to the database file, you can see your .db files in the 'db' directory.
// There will be one for development and one for production.
// The development one will be named 'database.dev.db' and the production one will be named 'database.db' (or whatever you set the DB_NAME to).
const DB_PATH = path.resolve(ROOT_DIR, 'db', `${DB_NAME}.${IS_PROD ? 'db' : 'dev.db'}`); // this just resolves the the absolute path to the database file.

// Here is where we check if the ORIGIN is not defined in production mode.
if (IS_PROD && !ORIGIN) {
  const errorMessage = 'ORIGIN environment variable is required in production mode';
  logger.error(errorMessage);
  throw new Error(errorMessage);
}

// If the "db" directory doesn't exist (where you store the db files) we create it.
// This is because we don't push the .db files to the repository, and git doesn't upload empty directories, so if you clone this, you probably can't see any 'db' folder until the server runs for the first time
// Also if we are in development mode and the database file exists, we delete it to reset the database.
// See how based on how because of how the DB_PATH is setup, we can easily refer to the db file by just using the DB_PATH variable.
// The DB_PATH variable will point to the correct file based on the environment we are in.
if (!fs.existsSync(path.dirname(DB_PATH))) {
  // if ./db doesn't exist, create it
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  logger.info(`Created directory for the database at ${path.dirname(DB_PATH)}`);
} else if (IS_DEV && fs.existsSync(DB_PATH)) {
  // in dev mode, we reset the database (delete the file, and `new Database('filename')` will create it if it doesn't exist)
  logger.info(`Resetting the database at ${DB_PATH}`);
  fs.rmSync(DB_PATH);
}

// Creates a connection to the database.
// If the database file doesn't exist, it will be created else it will attach to the existing database.
const db = new Database(DB_PATH);

// Initialize the database with the schema (shape of the database - think of it like the table definitions)
// This is not the best way to do this, usually you would use a specific migration strategy to handle sql scripts.
// We'll see another time how to, first create our own simple migration strategy and then after that, use a library and see how usually migrations are handled with other tools.
// ---------------------
// NOTE: By 'migration', we mean the process of moving the database from one version to another.
// On version 1 for example, you might have a User table with only a username and password.
// On version 2, you decide that you want to add an email column to the User table.
// To do this, you would create a 'migration script' that would alter the User table to add the email column.
// For example, this is the sql that does exactly that: `ALTER TABLE User ADD COLUMN email TEXT;`
// See https://www.sqlitetutorial.net/sqlite-alter-table/ for the ALTER TABLE syntax.
db.exec(`
  CREATE TABLE IF NOT EXISTS User (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    password TEXT NOT NULL,

    session_token TEXT DEFAULT NULL
  );
  `);
logger.info('Database initialized');

const app = express();

// CORS is being configured through headers.
// The `cors()` middleware allows us to easily configure CORS without manually setting headers, but note that it's not necessary to use it and we could've done it ourselves.
// For example, the origin option below is equivalent to setting the `Access-Control-Allow-Origin` header in the response.
// ---------------------
// CORS is a security feature implemented in specifically browsers (other environments can implement CORS but usually it's a browser feature, to ensure safe cross-origin requests).
// The setting of CORS is just us telling the browser how to behave when it comes to cross-origin requests through the HTTP headers.
// The browser is the one that will enforce these rules. Other environments like Postman or cURL (curl command, used in the terminal to craft HTTP requests) will not care about CORS.
// ---------------------
// Again, CORS is just a security feature that the browsers implement to protect the users. It's not a feature of the server to protect itself.
// And this feature can be enabled or configured through these headers we are setting.
// ---------------------
// Without settings CORS, the browser will fall back to the Same-Origin Policy, which means that the browser will prevent the frontend from making
// requests to a different origin.
// ---------------------
// NOTE: An origin consists of the protocol, domain, and port.
// For example, http://localhost:3000 and http://localhost:5173 are different origins.
app.use(
  cors({
    origin: ORIGIN, // valid options are: `*` (regexp string - asterisk allows all origins), `true` (boolean value, reflect the request origin), a string (specify the origin specifically), or an array of all of this for multiple origins
    optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204 (comment taken from: https://expressjs.com/en/resources/middleware/cors.html)
    credentials: true, // By default, browsers will not send cook
  })
);

// `helmet()` sets some default security headers, for the exact ones see: https://helmetjs.github.io/
app.use(helmet());

// `express.json()` is a middleware provided by Express to help us parse the body of the request as JSON.
// Without this, we would have to parse the JSON ourselves from the request.
// See https://stackoverflow.com/a/34915723/20967098 for how to do it without this middleware.
app.use(express.json());

// This middleware is used to parse the cookies from the request and make them available in `req.cookies` object.
// Without this, we would have to parse the cookies ourselves from the headers of the request. See the /sauce route for more.
app.use(cookieParser());

// This is a custom middleware to log every request being made to our server.
app.use((req, _, next) => {
  logger.info(`${req.method} ${req.url}`);
  next();
});

app.get('/', (_, res) => {
  // NOTE: If you don't specify a status code, it will default to 200, so you could omit the status code here.
  // Reasons to write it, even if it's the default are:
  // - Being explicit and clear about the status code. If you don't specify, you need to remember that 200 is the default.
  // - Consistency. You can always craft your responses in the same way and be explicit, so that it's easier to read and understand. (for example always the .status() before the .send())
  // ---------------------
  // Also, you see we are returning immediately. Still don't need it but when using `if` statements, it'll be handy to be able to stop the further execution of the function.
  // NOTE: res.send() doesn't NOT stop the execution of the function, it just sends the respond and the function continues to execute.
  // ---------------------
  // Your options are: return the response (`return res.send()`) or returning after we res.send() like:
  // res.send();
  // return;
  // ---------------------
  // I don't think there is any issue to just return the response directly, it's also more readable since it's 1 line.
  // The express doesn't do anything with the returned value, so it's just a matter of style.
  // I think the combination of `return res.send()` is very easy to read and immediately understand that:
  // - We are sending a response
  // - We are returning from the function
  return res.status(200).send({ message: 'Server is up and running' });
});

app.post('/register', (req, res) => {
  const { username, email, password } = req.body; // This is what `express.json()` does for us, no need to parse the JSON ourselves.

  // NOTE: Never inject user input directly into the SQL query string. This is to prevent SQL injection attacks.
  // Example, imagine you craft the query string like this:
  // const UNSAFE_QUERY = `SELECT email FROM User WHERE username = '${username}'`;

  // There are many ways to exploit this, depends also on what UNSAFE_QUERY is used for, but a simple example would be if the
  // username wasn't a username but a string like: `'; DROP TABLE User; --`
  // The quote `'` ends the string
  // The semicolon `;` ends the current query, then `DROP TABLE User;` would delete the User table, and `--` is to comment out the rest of the query (to prevent syntax errors, if the query is continued after the username).
  // So now the result query when injected would be:
  // const RESULT_UNSAFE_QUERY = db.exec(`SELECT email FROM User WHERE username = ''; DROP TABLE User; --`);

  // And now, neither the User table exists, nor the data. And the user now can execute anything they want.
  // And if the result is being returned to the attacker in any way, that means the attacker can not only execute queries but also read from the database:
  // res.send(RESULT_UNSAFE_QUERY);
  // Now, you're also leaking data to the attacker.
  // ---------------------
  // This was an example of SQL injection, and how you prevent this is by sanitizing the input, by sanitization we mean things like:
  // - Escaping the single quotes `'` by doubling them `''` or escaping them with a backslash `\'` (this prevents the user from ending the string and injecting their own SQL).
  // - Validating the input, for example, if you expect an email, validate that the input is an email format. (using regexp patterns for example)
  // and probably more, but that's the idea.
  // ---------------------
  // Usually, you use a library to handle this for you. Sometimes, your database library (in our case, `better-sqlite3`) provides a way to handle this.
  // in better-sqlite3, you can use `prepare` to prepare a statement with placeholders, and then bind the values to the placeholders.
  // For example:
  // const safeQuery = db.prepare('SELECT email FROM User WHERE username = ?').get(username);

  // And now, the sanitization happens by the library. On probably every database library, you'll see a similar way of doing this.
  // First prepare the query with placeholders, then bind the values to the placeholders and execute the query.

  // Now, back to the register route
  // This is the schema for username, password and email:
  // ---------------------
  // username TEXT NOT NULL UNIQUE,
  // email TEXT NOT NULL,
  // password TEXT NOT NULL,
  // ---------------------
  // What does this says to us?
  // - username is unique, so we can't have two users with the same username.
  // - a user must have a username, email, and password.
  // - two or more users can have the same email (if we don't want that we need to make the email unique too).
  // ---------------------
  // So, first we look up if ther user with this username already exists.
  // NOTE: You could also do some validation on the email and password at this point.
  //       'validator' is a good popular library for this, it contain many useful functions to validate strings.
  //       For example, you can validate emails, integers, dates, colors, currencies, IBANs, IPs, UUIDs... and many more.
  //       See: https://github.com/validatorjs/validator.js (you can also use it in the frontend)
  const userExists = db.prepare('SELECT username FROM User WHERE username = ?').get(username);

  if (userExists) {
    // '400' HTTP code is for 'Bad Request', see more: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/400
    logger.info(`Registration failed for ${username} because the user already exists`);
    return res.status(400).send({ message: 'User already exists' });
  }

  // Now we know the user doesn't exist, so we can insert the user into the database.
  // db.prepare('INSERT INTO User (username, email, password) VALUES (?, ?, ?)').run(username, email, password);
  // ---------------------
  // Or actually not, because we should never just store the passwords in plain text.
  // What we do, is we hash them. For that we're using a library called 'bcrypt'.
  // See https://github.com/kelektiv/node.bcrypt.js
  // NOTE: I'm going to use the sync version of the functions, because sync code is much easier to understand but
  //       once you get more comfortable with the code, you should probably use the async version.
  //       That's why cryptographic operations are usually heavy and can block the event loop which in node means blocking the whole server if we do it synchronously.
  // Recommend to read the usage docs here to take an idea on the API: https://github.com/kelektiv/node.bcrypt.js?tab=readme-ov-file#usage
  // ---------------------
  // EXPLANATION of the idea of hashing passwords
  // Hashing is one-way encryption. You input a string (the plain password string)
  // and you get a hash (a string that looks like you smashed your head in your keyboard after you realize you lost/leaked your data because of SQL Injection).
  // The idea is no one can reverse the hash to get the original password.
  // But the magic thing, that makes this whole hashing thing work, is that if you input the same string, you'll get the same hash.
  // So while we can't know the original password, we can compare the hashed passwords with the same algorithm and if they result in the same hash, we know the passwords are the same.
  // For now, we'll just hash and store the hash in the database. See /login route for how we compare the passwords.

  // This is how we do it with bcrypt (sync version):
  // first we need the 'salt'. A 'salt' is a random string that is added to the password before hashing.
  // It enhances the security of the hash by preventing some attacks like the 'rainbow table attack'.
  // You really don't need to know more than that. 'bcrypt' handles all of that.
  const saltRounds = 10; // this is the number of rounds the algorithm will run to generate the hash. The higher the number, the more secure but also the slower. They use 10 in the docs, so it seems like a good default.
  const salt = bcrypt.genSaltSync(saltRounds); // this generates the salt (the random string)
  const hashedPassword = bcrypt.hashSync(password, salt); // this applies the salt to the password and generates the hash.

  // And now we can insert the user into the database with the hashed password.
  db.prepare('INSERT INTO User (username, email, password) VALUES (?, ?, ?)').run(username, email, hashedPassword);

  logger.info(`User ${username} registered successfully`);

  // '201' HTTP code is for 'Created', see more: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/201
  return res.status(201).send({ message: 'User created successfully' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Again, you can do validation here before continuing. See the above notes in the register route.

  // Now we look up the user in the database.
  // NOTE: Normally I would say avoid '*' and specify the columns but it's fine, we just have a couple of columns.
  // But a reminder that now the user is either null (if user does NOT exists) or it's an object with the column names as keys.
  // user.id, user.username, user.email, user.password and user.session_token
  const user = db.prepare('SELECT * FROM User WHERE username = ?').get(username);

  if (!user) {
    logger.info(`Login failed for ${username} because the user does not exist`);
    return res.status(400).send({ message: 'Invalid credentials' });
  }

  // Now we need to validate the password.
  // The idea of a hash is that if you input the same string, you'll get the same hash.
  // So while we don't know the original password, we can still compare the hashes.
  // 'bcrypt' provides a function to do this very easily (again, this is the sync version).
  const isValidPassword = bcrypt.compareSync(password, user.password);
  // We don't even need to re-hash the password from the request, bcrypt does it for us
  // and then compares the hash the stored hash and returns a boolean, whether they match or not.

  // Again, the whole point of the hash is:
  // - For the same input, you get the same hash.
  // So because of this, we avoid storing the password in plain text and we can still compare the passwords.

  if (!isValidPassword) {
    logger.info(`Login failed for ${username} because the password is incorrect`);
    return res.status(400).send({ message: 'Invalid credentials' });
  }

  // ---------------------
  // Usually, by 'auth' usually we mean 2 thigns:
  // - Authentication: The process of verifying the identity of the user.
  // - Authorization: The process of verifying what the user is allowed to do.

  // Right now, we've done the authentication part, we've verified the identity of the user.
  // We know the user is who they say they are (this is because they matched their password).
  // But the remember, we want to restrict access to some parts of the application to only authenticated users.

  // If we were hosting the html files on the server, we could use this strategy to prevent the whole page from being accessed by unauthenticated users.
  // But since we want to serve the frontend through a different server (like Vite with React) we don't have a say in what the user can access (especially since in a CSR app)
  // In a CSR app (Client-Side Rendered app), even if you hide something, everything is visible to the user. By messing with the javascript, they can access anything. So there is no 'hiding' things in the frontend.

  // And in terms of the UI, the frontend should be responsible for showing a message to the user that they are not authenticated and they need to login to access that part of the application.
  // ---------------------

  // So, the idea of 'session authentication' is this:
  // 1. When logging in, we generate a 'session token' for the user, and store it in the database for that user.
  // 2. After storing it, we respond to the user with the session token.
  // 3. The user is responsible for sending this session token with every request they make to the server.

  // Now how do we sent it and how does the user sends to the server the token back, to access the restricted parts?
  // For this we use headers. We send the session token through headers. The user then will automatically send the headers with every request they make.
  // ---------------------
  // NOTE: For same-origin requests, the browser will (I think at least) automatically send the headers on each request.
  //       But, for cross-origin requests, you'll need to set the `credentials: 'include'` option in the fetch function in the frontend.
  //       This is because by default, the browser will not send cookies or specific headers to a different origin to prevent attacks.
  //       So for that, you have to be explicit and tell the browser to send the headers through the `credentials` option.

  // Your options on sending the session token are:
  // - Cookies: You can set a cookie with the session token. The browser will automatically send the cookie with every request to the server (the same-cross origin thing applies here).
  // - Headers: Techinically cookies are also headers, but there is a specific header called 'Authorization'. See more: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
  //            There is not really much difference between the two. You can use either, but in this case, I'm going to use a cookie to store the session token.
  // - Any other option: You can send it in query params (?sessionToken=...), you can just send in the body or whatever, but then you'll have to send it manually back.
  //                     Added this for completeness, you shouldn't send sensitive tokens through query params or the body.

  // So, let's start by generating the session token.
  const sessionToken = crypto.randomUUID(); // This generates a random UUID.
  // Normally you want the session token to be unique. No other user should have the same session token.
  // If they do and they are aware of this, they can impersonate the other user.
  // From what I know, the randomUUID() will guarantee a good uniqueness so we don't need to worry much about it.
  // If you want you could definitely check if a user with that session token already exists and generate a new one if it does, check again, until you find a unique one.
  // But probably not necessary ?! I think.

  // Now we store the session token in the database.
  db.prepare('UPDATE User SET session_token = ? WHERE username = ?').run(sessionToken, username);

  // Now we can respond to the user with the session token.
  // We can set the cookie through res.setHeader() but express provides also this res.cookie API for much easier setting of cookies.
  // Remember, a cookie is a key value pair. So 'session_token' is the key and the value is the `sessionToken`.
  // The third argument is the options (see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#attributes for the options):
  // - HttpOnly: This prevents the cookie from being accessed through javascript. You can't access the cookie in the frontend through document.cookie. It will not show up.
  //             (If you want to debug, you can see all the cookies, http-only included in the 'Application' Tab in the browser dev tools under 'Cookies')
  // - SameSite: This is what prevents the browser from sending the cookie (which is basically just a header) with cross-origin requests.
  //             'Lax' is the default value, which allows some cross-origin requests but not all. 'Strict' prevents ALL the cross-origin requests from sending the cookie.
  // - Secure: This tells the browser to send cookies only over HTTPS (mind the S, that means the connection is secure - encrypted).
  //           There is an exception for localhost in which the cookies are also sent even if "Secure" header is set.
  //           That's because no person can access localhost other than you. Usually for development, where you don't have HTTPS set up.
  //           Right now I set it up to the IS_PROD variable, so we control it programmatically on whether we're in production or not.
  // ---------------------
  // NOTE: You might've notices that we send data through the network just by stringifying them with `JSON.stringify()`.
  //       You might think this is not secure, because what if someone in the middle intercepts the request and reads the data.
  //       Which is a valid concern, that's why HTTPS is important. HTTPS encrypts the data through asymmetric encryption (public and private keys that are being exchanged through the initial connection of client-server).
  //       That's why the "Secure" option is important, allowing cookies through HTTP means that the data that is being sent are not encrypted and can be read by anyone.
  //       Remember in HTTP (specifically HTTP/1.1 version) the data are sent in plain text. A request (status line + headers + body) is just a string that is sent over the network.
  //       - If we send it through HTTP, then the request (status line + headers + body) are visible to anyone who can intercept the request.
  //       - If we send it through HTTPS, then the request (status line + headers + body) are encrypted and only the client and the server can read the data.
  logger.info(`User ${username} logged in successfully with session token: ${sessionToken}`);

  return res
    .cookie('session_token', sessionToken, { httpOnly: true, sameSite: 'lax', secure: IS_PROD })
    .status(200)
    .send({ message: 'Logged in successfully' });
});

app.get('/sauce', (req, res) => {
  // If we didn't use the 'cookie-parser' middleware, we would have to parse the cookies from the headers ourselves from the request object.
  const sessionToken = req.cookies.session_token;
  logger.info(`User with session token ${sessionToken} is trying to access the secret sauce`);

  // Now we can look up the user in the database with the session token.
  const authenticatedUser = db.prepare('SELECT * FROM User WHERE session_token = ?').get(sessionToken);
  
  if (!authenticatedUser) {
    logger.info('Unauthorized access to /sauce');
    return res.status(401).send({ message: 'Unauthorized' });
  }

  // And if the user is authenticated, we can respond with the restricted resource.

  // This is something silly for the example, you might query here for the user's tasks or messages or whatever you want.
  // The point is when you're here, you know that the user X is authenticated and you want to respond with some data that is related to this endpoint.
  // This where the user, you know is 'authorized' to access the data.
  const secretSauce =
    'https://png.pngtree.com/background/20230517/original/pngtree-cat-sits-among-pink-flowers-picture-image_2638477.jpg';
  logger.info(`User ${authenticatedUser.username} accessed the secret sauce`);

  return res.status(200).send({ sauce: `${secretSauce}` });
});

app.get('/logout', (req, res) => {
  // On logout, we do 2 things:
  // 1. We remove the session token from the database.
  // 2. We remove the session token from the user's cookies in the header.

  // 1. Remove the session token from the database.
  const sessionToken = req.cookies.session_token;
  if (!sessionToken) {
    logger.info('Logout failed because no session token provided');
    return res.status(400).send({ message: 'No session token provided' });
  }

  db.prepare('UPDATE User SET session_token = NULL WHERE session_token = ?').run(sessionToken);

  logger.info(`User with session token ${sessionToken} logged out successfully`);

  // 2. Remove the session token from the user's cookies in the header.
  res.clearCookie('session_token'); // `clearCookie()` is a function provided by express to remove a cookie. We could also use res.removeHeader() to remove a header.

  // NOTE: we could've also chain the res.clearCookie() with the .status() and .redirect()
  // I just did it like this to add comments to each step.
  return res.status(200).send({ message: 'Logged out successfully' });
});

// .listen() is what starts the server and makes it listen on the specified port for incoming requests.
app.listen(PORT, () => {
  logger.info(`Server is listening on port ${PORT}`);
});
