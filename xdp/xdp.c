#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <net/if.h>

#include <errno.h>
#include <stdlib.h>

#include "xdp.h"

#define XDP_MODE XDP_FLAGS_SKB_MODE

#define EXIT_OK                  0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL                1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION         2
#define EXIT_FAIL_XDP           30
#define EXIT_FAIL_BPF           40


int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
        int err;

        /* libbpf provide the XDP net_device link-level hook attach helper */
        err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
        if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
                /* Force mode didn't work, probably because a program of the
                 * opposite type is loaded. Let's unload that and try loading
                 * again.
                 */

                __u32 old_flags = xdp_flags;

                xdp_flags &= ~XDP_FLAGS_MODES;
                xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
                err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
                if (!err)
                        err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
        }
        if (err < 0) {
	    //fprintf(stderr, "ERP: "
            //            "ifindex(%d) link set xdp fd failed (%d): %s\n",
            //            ifindex, -err, strerror(-err));

                switch (-err) {
                case EBUSY:
                case EEXIST:
                        fprintf(stderr, "Hint: XDP already loaded on device"
                                " use --force to swap/replace\n");
                        break;
                case EOPNOTSUPP:
                        fprintf(stderr, "Hint: Native-XDP not supported"
                                " use --skb-mode or --auto-mode\n");
                        break;
                default:
                        break;
                }
                return EXIT_FAIL_XDP;
        }

        return EXIT_OK;
}

struct bpf_object *load_bpf_object_file(const char *filename, int ifindex)
{
        int first_prog_fd = -1;
        struct bpf_object *obj;
        int err;

        /* This struct allow us to set ifindex, this features is used for
         * hardware offloading XDP programs (note this sets libbpf
         * bpf_program->prog_ifindex and foreach bpf_map->map_ifindex).
         */
        struct bpf_prog_load_attr prog_load_attr = {
                .prog_type = BPF_PROG_TYPE_XDP,
                .ifindex   = ifindex,
        };
        prog_load_attr.file = filename;

        /* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
         * loading this into the kernel via bpf-syscall
         */

        err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
        if (err) {
                fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
                        filename, err, strerror(-err));
                return NULL;
        }

        printf("first_prog_fd %d\n",    first_prog_fd );

        //__u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
        __u32 xdp_flags = XDP_FLAGS_DRV_MODE;

        xdp_link_attach(ifindex, xdp_flags, first_prog_fd);

        /* Notice how a pointer to a libbpf bpf_object is returned */
        return obj;
}

static int xdp_link_detach(int ifindex, __u32 xdp_flags)
{
        /* Next assignment this will move into ../common/
         * (in more generic version)
         */
        int err;

        if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
                fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
                        err, strerror(-err));
                return EXIT_FAIL_XDP;
        }
        return EXIT_OK;
}

void *load_bpf_file(char *interface, char *filename, char *section) {

  int ifindex = if_nametoindex(interface);
  int err;

  __u32 xdp_flags = XDP_MODE;

  err = xdp_link_detach(ifindex, xdp_flags);
  if(err != EXIT_OK) {
      return NULL;
  }

  int prog_fd = -1;
  struct bpf_object *obj;
  struct bpf_program *bpf_prog;
  int offload_ifindex = 0;

  //__u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;


  /* If flags indicate hardware offload, supply ifindex */
  if (xdp_flags & XDP_FLAGS_HW_MODE)
    offload_ifindex = ifindex;

  /* Load the BPF-ELF object file and get back libbpf bpf_object */
  obj = load_bpf_object_file(filename, offload_ifindex);
  if (!obj) {
    fprintf(stderr, "ERR: loading file: %s\n", filename);
    exit(EXIT_FAIL_BPF);
  }


  bpf_prog = bpf_object__find_program_by_title(obj, section);
  if (!bpf_prog) {
    fprintf(stderr, "ERR: finding progsec: %s\n", section);
    exit(EXIT_FAIL_BPF);
  }

  prog_fd = bpf_program__fd(bpf_prog);
  if (prog_fd <= 0) {
    fprintf(stderr, "ERR: bpf_program__fd failed\n");
    exit(EXIT_FAIL_BPF);
  }
  xdp_link_attach(ifindex, xdp_flags, prog_fd);
  
  /* Notice how a pointer to a libbpf bpf_object is returned */
  return obj;
}



int xdp_link_detach2(char *interface) {
    int ifindex = if_nametoindex(interface);
    __u32 xdp_flags = XDP_MODE; //XDP_FLAGS_SKB_MODE;
    int err;
    
    xdp_link_detach(ifindex, XDP_FLAGS_DRV_MODE);

    err = xdp_link_detach(ifindex, xdp_flags);    
    if(err != EXIT_OK) {
        return -1;
    }

    return 0;
}

void *load_bpf_file2(char *filename) {
  
  struct bpf_object *obj;
  int offload_ifindex = 0;

  /* Load the BPF-ELF object file and get back libbpf bpf_object */
  obj = load_bpf_object_file(filename, offload_ifindex);
  if (!obj) {
    fprintf(stderr, "ERR: loading file: %s\n", filename);
    exit(EXIT_FAIL_BPF);
  }
  return obj;
}


int load_bpf_section(void *o, char *interface, char *section, int native) {
    struct bpf_object *obj = o;
    int prog_fd = -1;
    struct bpf_program *bpf_prog;
    int ifindex = if_nametoindex(interface);
    int err;

    printf("ifindex %s %d\n", interface, ifindex);
    
    __u32 xdp_flags = XDP_FLAGS_SKB_MODE;

    if (native) {
	xdp_flags = XDP_FLAGS_DRV_MODE;
    }
    
  
    err = xdp_link_detach(ifindex, xdp_flags);
    if(err != EXIT_OK) {
	//return NULL;
	return -1;
    }
  
    bpf_prog = bpf_object__find_program_by_title(obj, section);
    if (!bpf_prog) {
	fprintf(stderr, "ERR: finding progsec: %s\n", section);
	//exit(EXIT_FAIL_BPF);
	return -1;
    }
  
    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0) {
	fprintf(stderr, "ERR: bpf_program__fd failed\n");
	//exit(EXIT_FAIL_BPF);
	return -1;
    }
    
    
    err = xdp_link_attach(ifindex, xdp_flags, prog_fd);
    if(err) {
	return -1;
    }
    
    /* Notice how a pointer to a libbpf bpf_object is returned */
    return 0;
}

int load_bpf_section_generic(void *o, char *interface, char *section) {
    struct bpf_object *obj = o;
    int prog_fd = -1;
    struct bpf_program *bpf_prog;
    int ifindex = if_nametoindex(interface);
    int err;

    printf("ifindex %s %d\n", interface, ifindex);
    
    __u32 xdp_flags = XDP_FLAGS_SKB_MODE;
  
    err = xdp_link_detach(ifindex, xdp_flags);
    if(err != EXIT_OK) {
	//return NULL;
	return -1;
    }
  
    bpf_prog = bpf_object__find_program_by_title(obj, section);
    if (!bpf_prog) {
	fprintf(stderr, "ERR: finding progsec: %s\n", section);
	//exit(EXIT_FAIL_BPF);
	return -1;
    }
  
    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0) {
	fprintf(stderr, "ERR: bpf_program__fd failed\n");
	//exit(EXIT_FAIL_BPF);
	return -1;
    }
    
    
    err = xdp_link_attach(ifindex, xdp_flags, prog_fd);
    if(err) {
	return -1;
    }
    
    /* Notice how a pointer to a libbpf bpf_object is returned */
    return 0;
}


//////////////////////////////////////////////////////////////////////

int check_map_fd_info(int map_fd, int ks, int vs) {
    struct bpf_map_info info = { 0 };
    __u32 info_len = sizeof(info);
    int err;
    
    if (map_fd < 0)
	return -1;
    
    err = bpf_obj_get_info_by_fd(map_fd, &info, &info_len);
    if (err != 0)
	return -1;
    
    if (ks && ks != info.key_size) {
        fprintf(stderr, "ERR: %s() "
                "Map key size(%d) mismatch expected size(%d)\n",
                __func__, info.key_size, ks);
        return -1;
    }

    if (vs && vs != info.value_size) {
        fprintf(stderr, "ERR: %s() "
                "Map value size(%d) mismatch expected size(%d)\n",
                __func__, info.value_size, vs);
        return -1;
    }
    
    return 0;
}
