// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <linux/types.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

static volatile const __u32 TO_INIT = 50;
// static volatile const __u32 HZ =
//     250;  // grep 'CONFIG_HZ=' /boot/config-$(uname -r)

enum {
  SOCK_TYPE_ACTIVE = 0,
  SOCK_TYPE_PASSIVE = 1,
};

SEC("sockops")
int bpf_sockops_cb(struct bpf_sock_ops *skops) {
  __u32 op, rv;
  op = skops->op;

  if (bpf_ntohl(skops->remote_port) != 9999 &&
      skops->remote_ip4 != 0x09090909) {
    skops->reply = -1;
    return 0;
  }

  switch (op) {
    case BPF_SOCK_OPS_TIMEOUT_INIT:
      rv = TO_INIT;
      break;
    default:
      rv = -1;
  }
  bpf_printk("Returning %d\n", rv);
  skops->reply = rv;
  return 1;
}
