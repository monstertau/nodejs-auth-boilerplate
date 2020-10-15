const passport = require("passport");
const { Strategy: FacebookStrategy } = require("passport-facebook");
const { Strategy: LocalStrategy } = require("passport-local");
const { Strategy: JWTStrategy } = require("passport-jwt");
const { ExtractJwt: ExtractJWT } = require("passport-jwt");
const { User } = require("../database/models");
const bcrypt = require("bcrypt");

passport.use(
  "register",
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async (email, password, done) => {
      try {
        const user = await User.create({ email, password });
      } catch (error) {
        done(error);
      }
    }
  )
);

passport.use(
  "login",
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async (email, password, done) => {
      try {
        console.log(email);
        const user = await User.findOne({
          where: {
            email: email.toLowerCase(),
          },
        });
        console.log(user);
        if (!user) {
          return done(null, false, { message: "User not found" });
        }
        if (!bcrypt.compareSync(password, user.password)) {
          return done(null, false, { message: "Incorrect Password" });
        }
        return done(null, user, { message: "Logged in Successfully" });
      } catch (error) {
        done(error);
      }
    }
  )
);

passport.use(
  new JWTStrategy(
    {
      secretOrKey: process.env.JWT_KEY,
      jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    },
    async (jwt_payload, done) => {
      try {
        console.log(jwt_payload);
        const user = await User.findOne({
          where: {
            id: jwt_payload.id,
          },
        });

        if (!user) {
          return done(null, false, { message: "Wrong JWT Token!" });
        }
        return done(null, user, { message: "Logged in Successfully" });
      } catch (error) {
        done(error);
      }
    }
  )
);

passport.use(
  new FacebookTokenStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      fbGraphVersion: 'v3.0',
      profileFields: ['id', 'emails', 'name'],
    },
    // eslint-disable-next-line func-names
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const user = await UserModel.findOne({
          where: {
            // eslint-disable-next-line object-shorthand
            email: profile.emails[0].value,
          },
        });
        if (!user) {
          // If the user isn't found in the database, return a message
          return done(null, false, { message: 'User not found' });
        }

        // Send the user information to the next middleware
        return done(null, user, { message: 'Logged in Successfully' });
      } catch (error) {
        return done(error);
      }
    }
  )
);

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  done(null, user);
});
