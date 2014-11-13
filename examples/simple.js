var StrongBox = require('../');

// Create a new vault with a security profile and
// the fields that this vault will handle, with its respective encoding
var vault = new StrongBox({
  security: {
    password: 'Shhh_this_is_secret'
  },
  fields: {
    name: 'string',
    date: 'date',
    active: 'boolean',
    expire: 'date'
  }
});

// Lock something with the created vault
var buffer = vault.lock({
  name: 'John Doe',
  date: new Date(),
  active: true,
  expire: new Date()
});

console.log(buffer.toString('base64'));

// Your value is now a beautyfull encrypted buffer
// <Buffer e8 be ab 40 03 7f 00 00 80 c5 2c 01>

// To unlock/decrypt your buffer, youse the same vault
var user = vault.unlock(buffer);
console.log(user);

// And now you have your user back!
//
// { user: 'John'
//   date: Date(Wed Nov 05 2014 15:15:13 GMT-0200) }

