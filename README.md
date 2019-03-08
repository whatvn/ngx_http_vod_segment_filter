# ngx_http_vod_segment_filter

nginx module makes use of output filter to determine output of [nginx-vod-module](https://github.com/kaltura/nginx-vod-module), if vod module return empty ts segment, this module will send a redirect response which point player to next segment, prevent player from freezing because of error segment. 


# Install

```
./configure --add-module=/nginx_ts_filter_module
```


# Usage

`
ts_filter on;
` 


