// ebpf/loader.c
/*
 * - loader.c: 最终版
 * - 'dummy' 模式只加载 egress
 * - 'fixed'/'dynamic' 模式加载 ingress 和 egress
 */
#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/pkt_cls.h>
#include <signal.h>

// --- Default Parameters ---
#define DEFAULT_MIN_RATE_PPS 1000
#define DEFAULT_MAX_RATE_PPS 100000
#define DEFAULT_MAX_PROBABILITY 50
#define UPDATE_INTERVAL_SEC 1

enum operating_mode {
    MODE_DYNAMIC,
    MODE_FIXED,
    MODE_DUMMY,
};

// ... (struct state, cleanup, get_time_ns, usage... 都保持不变)
// ... (你可以从你现有的 loader.c 复制 cleanup, get_time_ns, usage)
struct state {
    __u64 packet_count;
    __u64 dropped_count;
    __u32 drop_probability;
};
static int ifindex_g;

static void cleanup(int sig) {
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex_g,
                        .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
    bpf_tc_hook_destroy(&hook);
    exit(0);
}

static __u64 get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: sudo %s <interface> --mode <dynamic|fixed|dummy> [options]\n\n"
        "Modes:\n"
        "  dynamic                Dynamically adjust probability based on traffic load.\n"
        "  fixed                  Set a fixed drop probability.\n"
        "  dummy                  Generate dummy packets with a fixed clone probability.\n\n"
        "Options for 'dynamic' mode:\n"
        "  --max-prob <int>         Maximum drop probability (0-100, default: %d)\n"
        "  --min-rate <int>         PPS rate to start dropping (default: %d)\n"
        "  --max-rate <int>         PPS rate to reach max probability (default: %d)\n\n"
        "Options for 'fixed' and 'dummy' modes:\n"
        "  --prob <int>             Fixed drop/clone probability (0-100, required for fixed/dummy mode)\n\n"
        "General options:\n"
        "  -h, --help               Display this help message\n"
        , prog, DEFAULT_MAX_PROBABILITY, DEFAULT_MIN_RATE_PPS, DEFAULT_MAX_RATE_PPS);
}
// --- (以上部分保持不变) ---

int main(int argc, char **argv) {
    struct bpf_object *bpf_obj;
    struct bpf_program *ing_prog = NULL, *eg_prog = NULL; // 初始化为 NULL
    int map_fd;
    __u64 last_time_ns = 0, last_packet_count = 0;

    enum operating_mode mode = -1;
    long prob = -1; 
    long max_prob = DEFAULT_MAX_PROBABILITY;
    long min_rate = DEFAULT_MIN_RATE_PPS;
    long max_rate = DEFAULT_MAX_RATE_PPS;
    int opt;

    static struct option long_options[] = {
        {"mode",     required_argument, 0,  0 },
        {"prob",     required_argument, 0, 'p'},
        {"max-prob", required_argument, 0, 'P'},
        {"min-rate", required_argument, 0, 'm'},
        {"max-rate", required_argument, 0, 'M'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    // ... (getopt_long 循环 和 参数验证... 保持不变)
    // ... (你可以从你现有的 loader.c 复制这部分)
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "p:P:m:M:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 0:
                if (strcmp("mode", long_options[option_index].name) == 0) {
                    if (strcmp("dynamic", optarg) == 0) {
                        mode = MODE_DYNAMIC;
                    } else if (strcmp("fixed", optarg) == 0) {
                        mode = MODE_FIXED;
                    } else if (strcmp("dummy", optarg) == 0) {
                        mode = MODE_DUMMY; 
                    } else {
                        fprintf(stderr, "Error: Invalid mode '%s'. Use 'dynamic', 'fixed', or 'dummy'.\n", optarg);
                        usage(argv[0]);
                        return 1;
                    }
                }
                break;
            case 'p': prob = atol(optarg); break;
            case 'P': max_prob = atol(optarg); break;
            case 'm': min_rate = atol(optarg); break;
            case 'M': max_rate = atol(optarg); break;
            case 'h': default: usage(argv[0]); return 1;
        }
    }
    if (mode == -1) {
        fprintf(stderr, "Error: Operating mode is required. Use --mode <dynamic|fixed|dummy>\n");
        usage(argv[0]);
        return 1;
    }
    if ((mode == MODE_FIXED || mode == MODE_DUMMY) && prob == -1) {
        fprintf(stderr, "Error: --prob is required for fixed or dummy mode.\n");
        usage(argv[0]);
        return 1;
    }
    if (mode == MODE_FIXED || mode == MODE_DUMMY) {
       if (prob < 0 || prob > 100) {
           fprintf(stderr, "Error: for fixed/dummy mode, --prob must be between 0 and 100.\n");
           return 1;
       }
    } else { // MODE_DYNAMIC
         if (max_prob < 0 || max_prob > 100) {
             fprintf(stderr, "Error: for dynamic mode, --max-prob must be between 0 and       100.\n");
             return 1;
         }  
      }
    if (optind >= argc) {
        fprintf(stderr, "Error: Interface name is required.\n");
        usage(argv[0]);
        return 1;
    }
    // --- (以上部分保持不变) ---

    const char *ifname = argv[optind];

    ifindex_g = if_nametoindex(ifname);
    if(ifindex_g == 0) { perror("if_nametoindex"); return 1;}
    
    // (选择 BPF 文件的逻辑... 保持不变)
    char bpf_obj_path[256];
    char *prog_dir = strdup(argv[0]);
    char *dir_path = dirname(prog_dir);
    const char *bpf_file_name;
    if (mode == MODE_DUMMY) {
        bpf_file_name = "dummy_generator.bpf.o";
        printf("--- Loading DUMMY PACKET GENERATOR (Egress-Clone Strategy) ---\n");
    } else {
        bpf_file_name = "packet_dropper.bpf.o";
        if (mode == MODE_FIXED) {
            printf("--- Loading PACKET DROPPER (FIXED mode) ---\n");
        } else {
            printf("--- Loading PACKET DROPPER (DYNAMIC mode) ---\n");
        }
    }
    snprintf(bpf_obj_path, sizeof(bpf_obj_path), "%s/%s", dir_path, bpf_file_name);
    free(prog_dir);
    
    // (BPF 加载逻辑... 保持不变)
    bpf_obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (libbpf_get_error(bpf_obj)) { return 1; }
    if (bpf_object__load(bpf_obj)) { bpf_object__close(bpf_obj); return 1; }

    // --- (*** 关键修复 ***) ---
    // 1. Egress 程序是 *必须* 的
    eg_prog = bpf_object__find_program_by_name(bpf_obj, "handle_egress");
    if (!eg_prog) { 
        fprintf(stderr, "Finding 'handle_egress' program failed\n"); 
        bpf_object__close(bpf_obj); 
        return 1; 
    }

    // 2. Ingress 程序是 *可选* 的
    //    (dummy 模式没有 ingress, fixed/dynamic 模式有)
    ing_prog = bpf_object__find_program_by_name(bpf_obj, "handle_ingress");
    if (!ing_prog) {
        if (mode == MODE_DUMMY) {
            printf("[INFO] 'handle_ingress' not found, which is correct for dummy mode.\n");
        } else {
            fprintf(stderr, "Warning: 'handle_ingress' not found (required for fixed/dynamic mode)\n");
            // 你也可以选择在这里报错退出
        }
    }
    // --- (*** 修复结束 ***) ---

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex_g, .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) { fprintf(stderr, "Failed to create TC hook: %s\n", strerror(-err)); bpf_object__close(bpf_obj); return 1; }

    // --- (*** 关键修复 2 ***) ---
    // 3. 只有在 ing_prog 存在时才附加它
    if (ing_prog) {
        DECLARE_LIBBPF_OPTS(bpf_tc_opts, ing_opts, .prog_fd = bpf_program__fd(ing_prog), .flags = BPF_TC_F_REPLACE);
        hook.attach_point = BPF_TC_INGRESS;
        err = bpf_tc_attach(&hook, &ing_opts);
        if (err) { fprintf(stderr, "Failed to attach ingress program: %s\n", strerror(-err)); cleanup(0); return 1; }
        printf("[INFO] Attached ingress program.\n");
    }
    // --- (*** 修复结束 ***) ---

    // 4. Egress 程序总是附加
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, eg_opts, .prog_fd = bpf_program__fd(eg_prog), .flags = BPF_TC_F_REPLACE);
    hook.attach_point = BPF_TC_EGRESS;
    err = bpf_tc_attach(&hook, &eg_opts);
    if (err) { fprintf(stderr, "Failed to attach egress program: %s\n", strerror(-err)); cleanup(0); return 1; }
    printf("[INFO] Attached egress program.\n");

    map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "state_map");
    if (map_fd < 0) { fprintf(stderr, "Finding map failed\n"); cleanup(0); return 1; }
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    // ... (主循环 logic... 保持不变)
    // ... (你可以从你现有的 loader.c 复制这部分)
    if (mode == MODE_FIXED || mode == MODE_DUMMY) {
        __u32 key = 0;
        struct state fixed_state = { .packet_count = 0, .dropped_count = 0, .drop_probability = prob };
        if (bpf_map_update_elem(map_fd, &key, &fixed_state, BPF_ANY) != 0) {
            fprintf(stderr, "Error setting initial probability in map.\n");
            cleanup(0);
            return 1;
        }
        if (mode == MODE_FIXED) {
            printf("Fixed drop probability set to %ld%%\n", prob);
        } else {
            printf("Fixed clone probability set to %ld%%\n", prob);
        }
        while (1) {
            sleep(30); 
        }
    } else {
        printf("Dynamic drop mode active (MinPPS: %ld, MaxPPS: %ld, MaxProb: %ld%%)\n", min_rate, max_rate, max_prob);
        last_time_ns = get_time_ns();
        while (1) {
            sleep(UPDATE_INTERVAL_SEC);
            __u32 key = 0;
            struct state current_state;
            if (bpf_map_lookup_elem(map_fd, &key, &current_state) != 0) { continue; }
            __u64 current_time_ns = get_time_ns();
            __u64 time_diff_ns = current_time_ns - last_time_ns;
            __u64 count_diff = current_state.packet_count - last_packet_count;
            last_time_ns = current_time_ns;
            last_packet_count = current_state.packet_count;
            double pps = (double)count_diff * 1e9 / time_diff_ns;
            __u32 new_prob = 0;
            if (pps > min_rate) {
                if (pps >= max_rate) { new_prob = max_prob; }
                else { new_prob = (__u32)(((pps - min_rate) / (max_rate - min_rate)) * max_prob); }
            }
            current_state.drop_probability = new_prob;
            bpf_map_update_elem(map_fd, &key, &current_state, BPF_ANY);
        }
    }

    return 0; 
}
