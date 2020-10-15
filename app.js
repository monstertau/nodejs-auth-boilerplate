/**
 * Module dependencies.
 */
const express = require("express");
const compression = require("compression");
const bodyParser = require("body-parser");
const logger = require("morgan");
const chalk = require("chalk");
const errorHandler = require("errorhandler");
const dotenv = require("dotenv");
const flash = require("express-flash");
const path = require("path");
const passport = require("passport");
const expressStatusMonitor = require("express-status-monitor");
const sass = require("node-sass-middleware");
const multer = require("multer");
const upload = multer({ dest: path.join(__dirname, "uploads") });

/**
 * Load environment variables from .env file, where API keys and passwords are configured.
 */
dotenv.config({ path: ".env.dev" });

/**
 * Controllers (route handlers).
 */
const userController = require("./controllers/user.controller");

// /**
//  * API keys and Passport configuration.
//  */
// const passportConfig = require('./config/passport');

/**
 * Create Express server.
 */
const app = express();

/**
 * Connect to PostgreSQL.
 */

/**
 * Express configuration.
 */
app.set("host", process.env.HOST || "0.0.0.0");
app.set("port", process.env.PORT || 8080);
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");

app.use(expressStatusMonitor());
app.use(compression());
app.use(logger("dev"));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

require("./configs/passport");
app.use(passport.initialize());
app.use(passport.session());

app.use(flash());

// app.use((req, res, next) => {
//   if (req.path === "/api/upload") {
//     // Multer multipart/form-data handling needs to occur before the Lusca CSRF check.
//     next();
//   } else {
//     lusca.csrf()(req, res, next);
//   }
// });
app.use(
  "/",
  express.static(path.join(__dirname, "public"), { maxAge: 31557600000 })
);
app.use(
  "/js/lib",
  express.static(path.join(__dirname, "node_modules/chart.js/dist"), {
    maxAge: 31557600000,
  })
);
app.use(
  "/js/lib",
  express.static(path.join(__dirname, "node_modules/popper.js/dist/umd"), {
    maxAge: 31557600000,
  })
);
app.use(
  "/js/lib",
  express.static(path.join(__dirname, "node_modules/bootstrap/dist/js"), {
    maxAge: 31557600000,
  })
);
app.use(
  "/js/lib",
  express.static(path.join(__dirname, "node_modules/jquery/dist"), {
    maxAge: 31557600000,
  })
);
app.use(
  "/webfonts",
  express.static(
    path.join(__dirname, "node_modules/@fortawesome/fontawesome-free/webfonts"),
    { maxAge: 31557600000 }
  )
);

/**
 * Primary app routes.
 */
app.post("/login", userController.postLogin);
app.get("/test", userController.getTest);
app.post("/signup", userController.postSignUp);
/**
 * Error Handler.
 */
if (process.env.NODE_ENV === "development") {
  // only use in development
  app.use(errorHandler());
} else {
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).send("Server Error");
  });
}

/**
 * Start Express server.
 */
app.listen(app.get("port"), () => {
  console.log(
    "%s App is running at http://%s:%d in %s mode",
    chalk.green("✓"),
    app.get("host"),
    app.get("port"),
    app.get("env")
  );
  console.log("  Press CTRL-C to stop\n");
});

module.exports = app;
