---
title: Broken Access Control
description: Improper implementation of enforcing access to resources
---
- [ ] Hidden functionality
- [ ] Look in JavaScript for hidden URL
- [ ] Look for parameters that can change role e.g. `Admin=false`
- [ ] IDOR e.g. `"roleid":2`
- [ ] Injecting `X-Original-URL: /invalid` to see if system process it
- [ ] Change method e.g. `POST` → `POSTX` if `"missing parameter"` the server maybe not be checking the method
- [ ] Parameters like `id` change to different value
- [ ] Finding object ID
- [ ] Performing restricted action with standard user session
- [ ] Add `Referer` header → some apps check if you're coming from admin and grant permission based on that
