void *load_bpf_file(char *, char *, char *);
int check_map_fd_info(int, int, int);


void *load_bpf_file2(char *);
int xdp_link_detach2(char *);
int load_bpf_section(void *, char *, char *, int);
int load_bpf_section_generic(void *, char *, char *);
