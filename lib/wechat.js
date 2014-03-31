var crypto = require('crypto')

var mp_xml = require('./xml')

function calcSig(token, timestamp, nonce) {
  var s = [token, timestamp, nonce].sort().join('');
  return crypto.createHash('sha1').update(s).digest('hex');
}

/**
 * Check signature
 */
function checkSig(token, query) {
  if (!query) return false
  var sig = query.signature;
  return query.signature === calcSig(token, query.timestamp, query.nonce);
}

function defaults(a, b) {
  for (var k in b) {
    if (!(k in a)) {
      a[k] = b[k];
    }
  }
}

function parseXML(req, callback) {
  var b = ''
  req.on('data', function(data) { b += data });
  req.on('end', function() {
    var data
    try {
      data = mp_xml.parse(b);
    } catch (e) {
      return callback(e);
    }
    callback(null, data);
  });
}

/**
 *
 * New Wechat MP instance, handle default configurations
 *
 * Options:
 *
 *    `token`      - wechat token
 *
 */
function Wechat(options) {
  if ('string' == typeof options) {
    options = {token: options};
  }

  return function(req, res, next) {

    var token = options.token;
    if (!checkSig(token, req.query)) {
      return res.status(401).end('Invalid signature');
    }
    if (req.method == 'GET') {
      return res.end(req.query.echostr);
    }
    if (req.method == 'HEAD') {
      return res.end();
    }
    parseXML(req, function(err, data) {
      if (err) {
        res.statusCode = 400;
        return res.end();
      }

      res.wechat = function(body) {
        var data = req.wechat || {};
        var reply = body || { content: '' };

        // fill up with default values
        reply.uid = reply.uid || data.uid;
        reply.sp = reply.sp || data.sp;
        reply.msgType = reply.msgType || 'text';
        reply.createTime = reply.createTime || new Date();

        res.setHeader('Content-Type', 'application/xml');
        res.end(mp_xml.build(reply));
      };

      req.wechat = data;
      next();
    });
  };
}


module.exports = Wechat;
