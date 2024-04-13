//npm install bcrypt
const bcrypt = require('bcrypt');

function hashPassword(password) {
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    return hash;
}

const password = 'mypassword';

const hashedPassword = hashPassword(password);
console.log('захешований пароль:', hashedPassword);

const userInput = 'mypassword';
const isPasswordCorrect = bcrypt.compareSync(userInput, hashedPassword);
console.log('пароль правильний:', isPasswordCorrect);
