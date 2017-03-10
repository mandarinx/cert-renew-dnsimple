var config          = require('./config');
var http            = require('http');
var util            = require('util');
var url             = require('url');
var fs              = require('fs');
var connect         = require('connect');
var sessions        = require('client-sessions');
var dnsimpleclient  = require('dnsimple');
var randomstring    = require('randomstring');
var bodyparser      = require('body-parser');
var request         = require('request');
var herokuclient    = require('heroku-client');

var redirect_uri = 'http://'+config.hostname+':'+config.port+'/auth';
var app = connect();
var cache_file = 'reqid_cache.txt';

app
    .use(sessions({
        cookieName: 'session',
        secret: config.session.secret
    }))
    .use(bodyparser.json());

var dnsimple = function(opts) {
    var baseUrl = 'https://api.dnsimple.com';
    return dnsimpleclient(Object.assign({
        baseUrl: baseUrl
    }, opts));
};

function errorHandler(req, res, error) {
    console.error(error);
    res.statusCode = 500;
    res.setHeader('Content-type', 'text/plain');
    res.end(util.inspect(error));
}

function notFoundHandler(req, res) {
    res.statusCode = 404;
    res.setHeader('Content-type', 'text/plain');
    res.end('not found');
}

function rootHandler(req, res) {
    res.statusCode = 200;
    res.end();
}

function getState() {
    return randomstring.generate(12);
}

function initHandler(req, res) {
    req.session.state = getState();
    var client = dnsimple({});

    var authUrl = client.oauth.authorizeUrl(config.clientId, {
        state:          req.session.state,
        redirect_uri:   redirect_uri
    });
    res.statusCode = 200;
    res.setHeader('Content-type', 'text/html');

    res.end('<a href="'+authUrl+'">Authorize</a>');
}

function initHerokuHandler(req, res) {
    req.session.state_heroku = getState();

    // var heroku = new herokuclient({
    //     token: process.env.HEROKU_API_TOKEN
    // });

    var authUrl = 'https://id.heroku.com/oauth/authorize?'+
        'client_id='+ process.env.HEROKU_OAUTH_ID +'&'+
        'response_type=code&'+
        'scope=read%20write&'+
        'state=' + req.session.state_heroku;

    res.statusCode = 200;
    res.setHeader('Content-type', 'text/html');

    res.end('<a href="'+authUrl+'">Authorize</a>');
}

function authHandler(req, res) {
    console.log('auth handler');
    var requestUrl = url.parse(req.url, true);
    console.log('req code: ' + requestUrl.query.code);

    if (requestUrl.query.error) {
        console.log('req query error');
        errorHandler(req, res, requestUrl.query.error_description);
        return;
    }

    var client = dnsimple({});

    client.oauth.exchangeAuthorizationForToken(
        requestUrl.query.code,
        config.clientId,
        config.clientSecret,
        {
            state:          req.session.state,
            redirect_uri:   redirect_uri
        }
    )

    .then(function(response) {
        var accessToken = response.access_token;
        req.session.accessToken = accessToken;
        console.log('access token: '+accessToken);
        client = dnsimple({
            accessToken: accessToken
        });
        console.log('whoami');
        // client.identity.whoami()
        return client.identity.whoami();
    }, function(error) {
        errorHandler(req, res, error);
    })

    .then(function(response) {
        var email = response.data.account.email;
        req.session.accountId = response.data.account.id;

        res.statusCode = 200;
        res.end(req.session.accountId);
        console.log(req.session.accountId+', '+email);
        // res.statusCode = 200;
        // res.setHeader('Content-type', 'text/html');
        // res.end(`
        //     <!DOCTYPE html>
        //     <html>
        //         <p>authorized as ${email}<p>
        //         <a href="/domains">list domains</a>
        //     </html>`);
    }, function(error) {
        errorHandler(req, res, error);
    });

    // get access token
    // check for req.hook_redirect

    // if (typeof req.hook_redirect !== 'undefined') {
    //     console.log('redir to '+req.hook_redirect);
    //     var handler = routes[req.hook_redirect];
    //     handler(req, res);
    //     return;
    // }

    // res.statusCode = 200;
    // res.setHeader('Content-type', 'text/html');

    // res.end('Authorized');
}

function authHerokuHandler(req, res) {
    res.statusCode = 200;
    res.setHeader('Content-type', 'text/html');
    res.end('Heroku');
}

function reissueHandler(req, res) {
    console.log('reissue certs');
    res.statusCode = 200;
    res.setHeader('Content-type', 'text/html');
    res.end('Reissue certs');
}

function certReissue(req, res) {
    console.log('cert hook');

    var client = dnsimple({
        accessToken: config.accessToken,
    });

    var cert;
    var account;
    var private_key;

    // Get account
    client.identity.whoami()
    .then(function(response) {
        account = response.data.account;

        console.log('ACCOUNT');
        console.log(account);
        console.log('');

        return client.certificates.listCertificates(account.id, config.domain);
    }, function(error) {
        errorHandler(req, res, error);
    })

    // Get certificate
    .then(function(response) {
        cert = response.data.filter(function(certificate) {
            return certificate.state === 'issued';
        })[0];

        console.log('CERT');
        console.log(cert);
        console.log('');

        return client.certificates.getCertificatePrivateKey(
            account.id,
            cert.domain_id,
            cert.id);

    }, function(error) {
        errorHandler(req, res, error);
    })

    // Get private key
    .then(function(response) {
        private_key = response.data.private_key;

        console.log('PRIVATE KEY');
        console.log(private_key);
        console.log('');

        res.statusCode = 200;
        res.end('Found certificate '+cert.id+' '+cert.common_name+' ');

    }, function(error) {
        errorHandler(req, res, error);
    });
}

function webhookHandler(req, res) {
    if (req.method !== 'POST') {
        res.statusCode = 500;
        res.end('Derp');
        return;
    }

    var route = hook_routes[req.body.name];
    if (!route) {
        res.statusCode = 404;
        res.end();
        return;
    }

    fs.readFile(cache_file, 'utf-8', function (err, data) {
        if (err) {
            console.log('error reading file');
            route(req, res);
        }

        if (data) {
            console.log('opened file');
            var lines = data.split('\n');

            // ignore this hook
            if (lines.indexOf(req.body.request_identifier) >= 0) {
                console.log('ignore hook');
                res.statusCode = 404;
                res.end();
                return;
            }

            console.log('process hook');
            lines.push(req.body.request_identifier);
            fs.writeFile(cache_file, lines.join('\n'));
            route(req, res);

        } else {
            console.log('empty file');
            fs.writeFile(cache_file, req.body.request_identifier + '\n');
            route(req, res);
        }
    });
}

function testHandler(req, res) {
    req.method = 'POST';
    var body = {
        name: 'certificate.reissue',
        api_version: 'v2',
        request_identifier: req.body.id
    };
    req.body = body;
    webhookHandler(req, res);
}

var hook_routes = {
    'certificate.reissue': certReissue
};

var routes = {
    '/':            rootHandler,
    '/init':        initHandler,
    '/init/heroku': initHerokuHandler,
    '/auth':        authHandler,
    '/auth/heroku': authHerokuHandler,
    '/reissue':     reissueHandler,
    '/webhook':     webhookHandler,
    '/test':        testHandler,
};

app.use(function(req, res) {
    var requestUrl = url.parse(req.url, true);
    var handler = routes[requestUrl.pathname];
    if (!handler) {
        notFoundHandler(req, res);
    } else {
        handler(req, res);
    }
});

var server = http.createServer(app);
server.listen(config.port, function() {
    var port = config.hostname === 'localhost' ? (':'+config.port) : '';
    console.log('Server listening on http://'+config.hostname+port+'/');
});
