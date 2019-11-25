# surge2clash
convert surge config to clash

if you have any problem, welcome to post an issue

# querystring option

| querystring option | description             |
| ------------------ | ----------------------- |
| url                | Surge configuration URL |
| data               | Base64 encoded string   |
| charSet            | Only applicable when passing configuration using `data` |
| win                | For Windows GUI         |


Examples: 

- `https://surge2clash.herokuapp.com/convert?url=https://yoursurge.conf/surge.conf&win=1`
- `https://surge2clash.herokuapp.com/convert?data=aW5wdXQ%3D&chatSet=utf-8&win=1`


Other options can also be changed using querystring such as `port`, `socks-port`, and `redir-port`.


