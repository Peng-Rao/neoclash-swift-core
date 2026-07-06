#ifndef CSWIFTCORE_TUN_H
#define CSWIFTCORE_TUN_H

#include <stddef.h>

/// Opens a TUN (layer-3) device and returns its file descriptor.
///
/// - macOS: opens a `utun` control socket. `requested_name` may be "utunN" to ask for a specific
///   unit, or NULL/"" to let the kernel pick the next free one.
/// - Linux: opens `/dev/net/tun` in `IFF_TUN | IFF_NO_PI` mode. `requested_name` may be "tunN" or
///   NULL/"" for a kernel-assigned name.
///
/// On success returns a non-negative fd and writes the assigned interface name into `name_out`
/// (NUL-terminated, truncated to `name_out_len`). On failure returns a negative errno.
int swiftcore_tun_open(const char *requested_name, char *name_out, size_t name_out_len);

#endif /* CSWIFTCORE_TUN_H */
