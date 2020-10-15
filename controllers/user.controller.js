const validator = require("validator");
const { User } = require("../database/models");
const jwt = require("jsonwebtoken");
const { json } = require("body-parser");
const passport = require("passport");
const bcrypt = require("bcrypt");
exports.postSignUp = (req, res, next) => {
  const { email, password, name } = req.body;
  if (!validator.isEmail(email)) {
    res.status(400).json({
      success: false,
      message: "Invalid email address",
    });
  }
  if (!name || validator.isEmpty(name)) {
    res.status(400).json({
      success: false,
      message: "User name cannot be blank",
    });
  }
  if (validator.isEmpty(password)) {
    res.status(400).json({
      success: false,
      message: "Password cannot be blank",
    });
  }
  if (validator.isLength(password, { min: 7 })) {
    res.status(400).json({
      success: false,
      message: "Password must contains at least 7 characters",
    });
  }

  User.findOne({ where: { email: email } }).then((user) => {
    if (user) {
      res.status(400).json({
        success: false,
        message: "Email has already taken",
      });
    }
  });

  const hashPassword = bcrypt.hashSync(password, 10);
  User.create({ name, email: email.toLowerCase(), password: hashPassword })
    .then((user) => {
      const payload = {
        email: user.email,
        id: user.id,
      };
      jwt.sign(
        payload,
        `${process.env.JWT_KEY}`,
        { expiresIn: "24h" },
        (err, token) => {
          if (err) {
            return res.status(400).json({
              success: false,
              message: err,
            });
          }
          return res.status(201).json({
            success: true,
            user: {
              id: user.id,
              name: user.name,
              email: user.email,
            },
            jwtToken: `Bearer ${token}`,
            expiresIn: `24h`,
          });
        }
      );
    })
    .catch((err) => {
      return next(err);
    });
};

exports.postLogin = (req, res, next) => {
  const { email, password } = req.body;
  if (!validator.isEmail(email)) {
    res.status(400).json({
      success: false,
      message: "Invalid email address",
    });
  }
  if (validator.isEmpty(password)) {
    res.status(400).json({
      success: false,
      message: "Password cannot be blank",
    });
  }
  passport.authenticate(
    "login",
    { session: false },
    async (err, user, message) => {
      try {
        if (err || !user) {
          return res.status(401).json({
            success: false,
            message: message.message,
          });
        }

        const payload = {
          email: user.email,
          id: user.id,
        };

        jwt.sign(
          payload,
          `${process.env.JWT_KEY}`,
          { expiresIn: "24h" },
          (err, token) => {
            if (err) {
              return res.status(400).json({
                success: false,
                message: err,
              });
            }
            return res.status(201).json({
              success: true,
              user: {
                id: user.id,
                name: user.name,
                email: user.email,
              },
              jwtToken: `Bearer ${token}`,
              expiresIn: `24h`,
            });
          }
        );
      } catch (error) {
        return next(error);
      }
    }
  )(req, res, next);
};




exports.getTest = (req, res, next) => {
  passport.authenticate("jwt", async (err, user, message) => {
    try {
      if (err || !user) {
        console.log(err);
        return res.status(400).json({
          success: false,
          message: "JWT Authentication Failed.",
        });
      }

      return res.status(200).json({
        success: true,
      });
    } catch (error) {
      next(error);
    }
  })(req, res, next);
};
