# Android-only Vision pointer hardening

Upstream: github.com/sagernet/sing-vmess v0.2.9-0.20261019223527-a0c58542bd9d.
License and original notices retained.

Modified vless/vision.go and vless/vision_utls.go: TLS registry results retain
unsafe.Pointer rather than carrying an object address through uintptr across
function returns. Buffer field access uses unsafe.Add. Construction checks
that both private TLS buffer fields exist, have the expected concrete types,
and lie within the reflected structure before dereferencing. Unsupported
layouts fail closed.

Reason: the original pointer arithmetic triggers a Go checkptr fatal error
when exercising Reality/Vision with the race/checkptr instrumentation enabled.
The fix passes these checks without disabling them. The implementation still
accesses pinned TLS internals, so upgrading Go/uTLS must repeat the protocol
and pointer-check tests. This copy is referenced only by Android go.mod;
existing Apple/Mac dependencies and caches are not patched.
