# wechat-mp 微信公众平台消息接口中间件 [![Build Status](https://travis-ci.org/node-webot/wechat-mp.png?branch=master)](https://travis-ci.org/node-webot/wechat-mp)

Utilities for wechat offical account messaging API.

校验签名，接受并解析微信消息，处理回复内容为 XML ，并回复给微信。

如需使用自定义菜单等高级接口，可使用 [wechat-api](https://www.npmjs.org/package/wechat-api) 模块。

## Express Middlewares

本模块主要作为 Connect/Express 框架的中间件使用：

```javascript
var mp = require('wechat-mp')(process.env.WX_TOKEN);
var app = require('express')();

app.use('/wechat', mp.start())
app.post('/wechat', function(req, res, next) {

  console.log(req.body);

  res.body = {
    content: 'Hi.'
    msgType: 'text'
  };

  next();
}, mp.end());
```

如果要在 [koa](http://koajs.com/) 里使用，可尝试 [koa-wechat](https://www.npmjs.org/package/koa-wechat) 模块。


### mp( *[options]* )

`options` can be either the token string or an object.
You can use these options both when initialization(`mp = require('wechat-mp')(options)`)
and `mp.start()`.


#### options.token

The token for wechat to check signature.

#### options.tokenProp

Default: 'wx\_token'

Will try get `req[tokenProp]` as token. Good for dynamically set token.

#### options.dataProp

Default: 'body'

Will put parsed data on `req[dataProp]`. So you can access wechat request message via `req.body` or `req.wx_data`, etc.

#### options.session

Unless `options.session` is set to `false`,
the `mp.start()` middleware will set `req.sessionID` and `req.sessionId`
to `"wx.#{toUserName}.#{fromUserName}"`.
So you can use `req.session` to save information about one specific user.

The `sessionId` cannot be changed by any other following middlewares.

To make this work, `mp.start()` must go before express/connect's session middleware.

```
app.use('/wechat', mp.start())
app.use(connect.cookieParser())
app.use(connect.session({ store: ... }))
```

## weixin-robot

使用 [wexin-robot](https://github.com/node-webot/weixin-robot) 模块，更傻瓜化地定义自动回复功能。

## 调试

使用 [webot-cli](https://github.com/node-webot/webot-cli) 调试发送测试消息。


## License

the MIT license.
