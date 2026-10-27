---
name: listener
description: d
---
nc -lvp 4444
python3 -m http.server 8000
