# HandleRedirect
Handle Redirect via BYOVD Kernel Read/Write

Handle Redirect via BYOVD Kernel Read/Write, a PoC that redirects a handle's kernel object pointer to a different EPROCESS, obtaining a fully functional handle to a sensitive process without ObRegisterCallbacks ever seeing the operation.

Full writeup: medium.com/@s12deff/handle-redirect-549902e6d868

----

EDR products register callbacks via ObRegisterCallbacks to intercept every OpenProcess call. When your process opens a handle to lsass, the EDR sees it and can strip access rights before the handle reaches you.

This technique avoids that entirely. Instead of calling OpenProcess on lsass, we call it on a dummy process (e.g. Notepad) and then, via a kernel write primitive, patch the ObjectPointerBits field inside our own handle table entry to point at the lsass _OBJECT_HEADER. The kernel follows the pointer without question — no callback fires.