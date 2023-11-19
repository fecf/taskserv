# taskserv

TaskServ is a Windows service that automatically runs periodic tasks.

### Usage

1. Create "taskserv.conf" in the same folder as "taskserv.exe" as follows

```
[xmouse]
when = "startup"
path = "C:\\Program Files\\Highresolution Enterprises\\X-Mouse Button Control\\XMouseButtonControl.exe"
 
[noborder]
when = "startup"
path = "C:\\dev\\tools\\noborder.exe"

[keyrate]
when = "startup"
path = "C:\\dev\\keyrate.exe"
args = ["165", "30"]

[rclone]
when = [{ "cron" = "0 0 2 * * * *" }, "trigger", "startup"]
path = "cmd"
args = ["/c", "r:\\env\\backup.bat"]
```

2. Start TaskServ service from command prompt (requires administrator rights).
```
taskserv start
```