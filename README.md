# surge2clash
Convert Surge configuration to Clash format

If you encounter any problems, please feel free to raise an Issue. 

##  Query String Options

| param| description | required |
| ---- | ---- | ---- |
| url | Surge configuration URL | required if `data` not exist |
| data | Base64 encoded string | required if `url` not exist |
| charSet | Only applicable when passing configuration using `data` | no |
| win | For Windows GUI | no |
| extraRulesData | Base64 encoded rules which will append to **top** of origin `Rule` | no |
| overrideRules | If exists, origin `Rule` section will be ignored | no |

## Examples: 

- `https://surge2clash.herokuapp.com/convert?url=https://yoursurge.conf/surge.conf&win=1`
- `https://surge2clash.herokuapp.com/convert?data=aW5wdXQ%3D&chatSet=utf-8&win=1`

Other options can also be changed using querystring such as `port`, `socks-port`, and `redir-port`.


