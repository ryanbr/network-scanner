Just examples of usage, always review the output before using publicly

Validate using;
* https://regex101.com/
* https://regexr.com/

| Domain                   | JSON Regex |
|:---------------------------|:------------|
| `/api/test/`             | `\\/api\\/test\\/` |
| `/rto.js`                | `\\/rto\\.js` |
| `/rto.min.js`            | `\\/rto\\.min\\.js$` |
| `.com/`                  | `\\.com\\/` |
| `/test/`                 | `\\/test\\/` |
| `/ab/cd.php?ev=`         | `\\/ab\\/cd\\.php\\?ev=` |
| `/ab/cde/ow/bra?`        | `\\/ab\\/cde\\/ow\\/bra\\?.*` |
| `dcbgh`                  | `dcbgh` |
| `/gts_test=`             | `\\/\\?gts_test=` |
| `abcdefghjk.top/`        | `^https?:\\/\\/[a-z]{8,19}\\.top\\/$` |
| `abcdefghjk.top/*`       | `^https?:\\/\\/[a-z]{8,19}\\.top\\/.*$` |
| `abcdefghjk.top/com`     | `^https?:\\/\\/[a-z]{8,19}\\.(top\|com)\\/$` |
| `abcdefghjk.top com/*`   | `^https?:\\/\\/[a-z]{8,19}\\.(top\|com)\\/.*$` |
| `.net/bar/`              | `\\.net\\/bar\\/` |
| `&test_me=`              | `&test_me=` |
| `/new/` `/test/`         | `\\/(new\|test)\\/` |
| `.com` or `.net`         | `\\.(com\|net)\\/` |       


