const got = require('../core/got');
const surge2Clash = require('../core/surge2clash');

module.exports = async (ctx, next) => {
  const { url, data, charSet = 'utf-8' } = ctx.query;
  if (data && data.length > 0) {
    // Use data first
    const buff = new Buffer(data, 'base64');
    ctx.body = surge2Clash(buff.toString(charSet), ctx.query);
  } else if (url && url.length > 0) {
    const res = await got(url);
    ctx.body = surge2Clash(res.body, ctx.query);
  } else {
    ctx.throw('Need to provide either URL of Surge configuration or Base64 encoded data!');
  }
  ctx.type = 'text/plain';
  await next();
};
