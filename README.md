# CHECKMK UPDATE RULESET

Add new rule "active_checks:http" type to existing ruleset using [Web-API](https://docs.checkmk.com/latest/en/web_api_references.html) via command-line

# Dependencies

- Python >= 3.7
- Checkmk 1.6.0p18
- automation user (reference [here](https://docs.checkmk.com/latest/en/web_api.html#automation))

# Usage

```shell
export CHECKMK_USER=myuser
export CHECKMK_PASSWORD=mypassword
export CHECKMK_URL=https://mycheckmk/mysite
update_ruleset.py myhost mymonitor 10.10.10.10 8080 /myapp
```