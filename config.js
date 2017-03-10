require('dotenv').config();

var config = {
    session: {
        secret:     'thisisasupersecretstring'
    },
    accessToken:    process.env.ACCESS_TOKEN,
    clientSecret:   process.env.CLIENT_SECRET,
    clientId:       process.env.CLIENT_ID,
    port:           process.env.PORT || 3333,
    hostname:       process.env.HOSTNAME,
    domain:         process.env.DOMAIN,
};

module.exports = config;
