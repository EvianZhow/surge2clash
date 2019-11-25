const Router = require('@eggjs/router');

const router = new Router();

router.get('/', async ctx => {
  ctx.body = 'hello';
});

router.get('/convert', require('./surge2clash'));

module.exports = router;
