# EasyPrivacy Generic Strings - JSON Regex Conversion

Tracking and analytics patterns converted to JSON-safe regex. Always validate before using.

Test patterns at:
* https://regex101.com/
* https://regexr.com/

## Event & Impression Tracking

| Pattern | JSON Regex |
|:--------|:-----------|
| `&EventType=DataDealImpression&` | `&EventType=DataDealImpression&` |
| `?logType=impression&` | `\\?logType=impression&` |
| `?groupType=engagement&eventType=CLICK&` | `\\?groupType=engagement&eventType=CLICK&` |
| `?type=page&event=` | `\\?type=page&event=` |
| `?event=performancelogger:` | `\\?event=performancelogger:` |
| `*view*pixel&` | `.*view.*pixel&` |

## Script Files & Resources

| Pattern | JSON Regex |
|:--------|:-----------|
| `-adobeDatalayer_bridge.js` | `-adobeDatalayer_bridge\\.js` |
| `_chartbeat.js` | `_chartbeat\\.js` |
| `/owa.tracker-combined-min.js` | `\\/owa\\.tracker-combined-min\\.js` |
| `.v4.analytics.` | `\\.v4\\.analytics\\.` |
| `/vli-platform/adb-analytics@` | `\\/vli-platform\\/adb-analytics@` |

## Tracking Endpoints

| Pattern | JSON Regex |
|:--------|:-----------|
| `.com/track?v=` | `\\.com\\/track\\?v=` |
| `/track?cb=` | `\\/track\\?cb=` |
| `/track.gif?data=` | `\\/track\\.gif\\?data=` |
| `/track_framework_metrics?` | `\\/track_framework_metrics\\?` |
| `/track/pageview?` | `\\/track\\/pageview\\?` |
| `-click-tracker.` | `-click-tracker\\.` |

## Service & Tracking IDs

| Pattern | JSON Regex |
|:--------|:-----------|
| `.svc/?tracking_id=` | `\\.svc\\/\\?tracking_id=` |
| `/get_site_data?requestUUID=` | `\\/get_site_data\\?requestUUID=` |
| `/ns.html?id=GTM-` | `\\/ns\\.html\\?id=GTM-` |
| `/tag/proxy?id=G-` | `\\/tag\\/proxy\\?id=G-` |
| `/sk-park.php?pid=` | `\\/sk-park\\.php\\?pid=` |

## PHP Action Parameters

| Pattern | JSON Regex |
|:--------|:-----------|
| `.php?action=browse&` | `\\.php\\?action=browse&` |
| `.php?action_name=` | `\\.php\\?action_name=` |
| `_stat.php?referer=` | `_stat\\.php\\?referer=` |
| `/pagelogger/connector.php?` | `\\/pagelogger\\/connector\\.php\\?` |

## Analytics & Performance

| Pattern | JSON Regex |
|:--------|:-----------|
| `/?essb_counter_` | `\\/\\?essb_counter_` |
| `/_i?referral_url=` | `\\/_i\\?referral_url=` |
| `/?livehit=` | `\\/\\?livehit=` |
| `/__ssobj/rum?` | `\\/__ssobj\\/rum\\?` |
| `/analytics/?event=` | `\\/analytics\\/\\?event=` |
| `/analytics/visit.php` | `\\/analytics\\/visit\\.php` |
| `/wpstatistics/v1/hit?` | `\\/wpstatistics\\/v1\\/hit\\?` |

## Logging & Experiments

| Pattern | JSON Regex |
|:--------|:-----------|
| `/?log=experiment&` | `\\/\\?log=experiment&` |
| `/?log=performance-` | `\\/\\?log=performance-` |
| `?log=stats-` | `\\?log=stats-` |
| `?log=xhl-widgets-events&` | `\\?log=xhl-widgets-events&` |
| `/_/_/logClientError/` | `\\/_\\/_\\/logClientError\\/` |
| `/hits/logger?` | `\\/hits\\/logger\\?` |

## Pixel & Image Tracking

| Pattern | JSON Regex |
|:--------|:-----------|
| `/anonymous_user_guid.gif?` | `\\/anonymous_user_guid\\.gif\\?` |
| `/0.gif?` | `\\/0\\.gif\\?` |
| `_c.gif?c=` | `_c\\.gif\\?c=` |
| `/urchin.html?` | `\\/urchin\\.html\\?` |

## Counters & Views

| Pattern | JSON Regex |
|:--------|:-----------|
| `/ViewCounter/` | `\\/ViewCounter\\/` |
| `/prod/ping?` | `\\/prod\\/ping\\?` |

## DataLayer & Google Analytics

| Pattern | JSON Regex |
|:--------|:-----------|
| `?[AQB]&ndh=1&t=` | `\\?[AQB]&ndh=1&t=` |
| `&l=dataLayer&cx=c` | `&l=dataLayer&cx=c` |

## Common Variations & Wildcards

| Pattern Type | Example | JSON Regex |
|:-------------|:--------|:-----------|
| **Any tracking script** | `*track*.js` | `.*track.*\\.js` |
| **Any analytics path** | `/*/analytics/*` | `\\/.*\\/analytics\\/.*` |
| **Any pixel tracking** | `*.gif?*` | `.*\\.gif\\?.*` |
| **Any log parameter** | `?*log*=*` | `\\?.*log.*=.*` |
| **Any event parameter** | `?*event*=*` | `\\?.*event.*=.*` |

## Advanced Patterns

| Use Case | Pattern | JSON Regex |
|:---------|:--------|:-----------|
| **Multiple parameters** | `?param1=value&param2=` | `\\?param1=value&param2=` |
| **Optional parameters** | `/path?optional_param` | `\\/path\\?.*optional_param` |
| **Subdomain tracking** | `tracking.*.com/` | `tracking\\..+\\.com\\/` |
| **Version in path** | `/v1/track` or `/v2/track` | `\\/v[0-9]+\\/track` |
| **Hash-based IDs** | `/track?id=abc123` | `\\/track\\?id=[a-zA-Z0-9]+` |


| Pattern                  | JSON Regex |
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
| `.net/bar/`              | `\\.net\\/bar\\/` |
| `&test_me=`              | `&test_me=` |
| `/new/` `/test/`         | `\\/(new\|test)\\/` |
| `.com` or `.net`         | `\\.(com\|net)\\/` |    

## Notes
- Use `.*` for wildcard matching (matches any characters)
- Escape dots: `.` ? `\\.`
- Escape slashes: `/` ? `\\/` 
- Escape question marks: `?` ? `\\?`
- Use `[a-zA-Z0-9]` for alphanumeric characters
- Use `+` for one or more characters
- Use `*` after `.` for zero or more characters
