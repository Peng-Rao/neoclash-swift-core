#include "cswiftcore_tun.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)

#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>

int swiftcore_tun_open(const char *requested_name, char *name_out, size_t name_out_len) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        return -errno;
    }

    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        int err = errno;
        close(fd);
        return -err;
    }

    /* sc_unit is 1-based: unit N maps to interface utun(N-1); 0 lets the kernel choose. */
    unsigned int sc_unit = 0;
    if (requested_name != NULL && requested_name[0] != '\0') {
        unsigned int parsed = 0;
        if (sscanf(requested_name, "utun%u", &parsed) == 1) {
            sc_unit = parsed + 1;
        }
    }

    struct sockaddr_ctl addr;
    memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = sc_unit;

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int err = errno;
        close(fd);
        return -err;
    }

    if (name_out != NULL && name_out_len > 0) {
        socklen_t len = (socklen_t)name_out_len;
        if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name_out, &len) < 0) {
            int err = errno;
            close(fd);
            return -err;
        }
    }
    return fd;
}

#elif defined(__linux__)

#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>

int swiftcore_tun_open(const char *requested_name, char *name_out, size_t name_out_len) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        return -errno;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (requested_name != NULL && requested_name[0] != '\0') {
        strncpy(ifr.ifr_name, requested_name, IFNAMSIZ - 1);
    }

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        int err = errno;
        close(fd);
        return -err;
    }

    if (name_out != NULL && name_out_len > 0) {
        strncpy(name_out, ifr.ifr_name, name_out_len - 1);
        name_out[name_out_len - 1] = '\0';
    }
    return fd;
}

#else

int swiftcore_tun_open(const char *requested_name, char *name_out, size_t name_out_len) {
    (void)requested_name;
    (void)name_out;
    (void)name_out_len;
    return -ENOSYS;
}

#endif
