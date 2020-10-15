const bcrypt = require("bcrypt");

exports.generatePasswordHash = async (password) => {
  const saltRounds = 8;
  return bcrypt.hash(password, saltRounds);
};
