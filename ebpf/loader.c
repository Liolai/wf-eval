// ebpf/loader.c
/*
 * 
 * - Supports: fixed, dynamic, dummy_fixed, dummy_dynamic, combined, ingress
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
    MODE_DYNAMIC,       // 动态丢包
    MODE_FIXED,         // 固定丢包 (Egress)
    MODE_INGRESS,       // 固定丢包 (Ingress)
    MODE_DUMMY,         // 固定假包 (旧 dummy，现在视为 dummy_fixed)
    MODE_DUMMY_DYNAMIC, // 动态假包 (新增)
    MODE_COMBINED       // 混合模式 (Drop + Dummy) (新增)
};

// 必须与 BPF 代码中的 struct state 定义完全一致！
struct state {
    __u64 packet_count;
    __u64 dropped_count;
    __u32 drop_probability;
    __u32 dummy_probability; // 新增字段：用于控制假包生成率
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
        "Usage: sudo %s <interface> --mode <mode> [options]\n\n"
        "Modes:\n"
        "  fixed            Fixed Drop (Egress)\n"
        "  ingress          Fixed Drop (Ingress)\n"
        "  dynamic          Dynamic Drop based on PPS\n"
        "  dummy            Fixed Dummy Injection (Egress)\n"
        "  dummy_dynamic    Dynamic Dummy Injection based on PPS\n"
        "  combined         Fixed Drop + Fixed Dummy (Mixed Defense)\n\n"
        "Options:\n"
        "  --prob <int>         Drop Probability (0-100) [Required for fixed/combined]\n"
        "  --dummy-prob <int>   Dummy Probability (0-100) [Required for combined]\n"
        "  --max-prob <int>     Max Probability for dynamic modes (default: %d)\n"
        "  --min-rate <int>     Min PPS to start triggering (default: %d)\n"
        "  --max-rate <int>     Max PPS to reach max prob (default: %d)\n"
        , prog, DEFAULT_MAX_PROBABILITY, DEFAULT_MIN_RATE_PPS, DEFAULT_MAX_RATE_PPS);
}

int main(int argc, char **argv) {
    struct bpf_object *bpf_obj;
    struct bpf_program *ing_prog = NULL, *eg_prog = NULL;
    int map_fd;
    __u64 last_time_ns = 0, last_packet_count = 0;

    enum operating_mode mode = -1;
    long prob = 0; 
    long dummy_prob = 0; // 新增：假包概率
    long max_prob = DEFAULT_MAX_PROBABILITY;
    long min_rate = DEFAULT_MIN_RATE_PPS;
    long max_rate = DEFAULT_MAX_RATE_PPS;
    int opt;

    static struct option long_options[] = {
        {"mode",       required_argument, 0,  0 },
        {"prob",       required_argument, 0, 'p'},
        {"dummy-prob", required_argument, 0, 'd'}, // 新增参数
        {"max-prob",   required_argument, 0, 'P'},
        {"min-rate",   required_argument, 0, 'm'},
        {"max-rate",   required_argument, 0, 'M'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "p:d:P:m:M:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 0:
                if (strcmp("mode", long_options[option_index].name) == 0) {
                    if (strcmp("dynamic", optarg) == 0) mode = MODE_DYNAMIC;
                    else if (strcmp("fixed", optarg) == 0) mode = MODE_FIXED;
                    else if (strcmp("ingress", optarg) == 0) mode = MODE_INGRESS;
                    else if (strcmp("dummy", optarg) == 0 || strcmp("dummy_fixed", optarg) == 0) mode = MODE_DUMMY;
                    else if (strcmp("dummy_dynamic", optarg) == 0) mode = MODE_DUMMY_DYNAMIC;
                    else if (strcmp("combined", optarg) == 0) mode = MODE_COMBINED;
                    else {
                        fprintf(stderr, "Error: Invalid mode '%s'\n", optarg);
                        return 1;
                    }
                }
                break;
            case 'p': prob = atol(optarg); break;
            case 'd': dummy_prob = atol(optarg); break;
            case 'P': max_prob = atol(optarg); break;
            case 'm': min_rate = atol(optarg); break;
            case 'M': max_rate = atol(optarg); break;
            case 'h': default: usage(argv[0]); return 1;
        }
    }

    if (mode == -1) {
        fprintf(stderr, "Error: --mode is required.\n");
        usage(argv[0]);
        return 1;
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: Interface name is required.\n");
        usage(argv[0]);
        return 1;
    }
    const char *ifname = argv[optind];
    ifindex_g = if_nametoindex(ifname);
    if(ifindex_g == 0) { perror("if_nametoindex"); return 1;}

    // --- BPF File Selection Strategy ---
    char bpf_obj_path[256];
    char *prog_dir = strdup(argv[0]);
    char *dir_path = dirname(prog_dir);
    const char *bpf_file_name;

    // 策略：
    // 1. 如果是 Dummy 相关或 Combined 模式，我们加载 dummy_generator.bpf.o
    //    (假设 dummy_generator 代码里已经包含了 clone 逻辑，并且 struct state 支持 drop_prob)
    // 2. 否则加载 packet_dropper.bpf.o
    if (mode == MODE_DUMMY || mode == MODE_DUMMY_DYNAMIC || mode == MODE_COMBINED) {
        bpf_file_name = "dummy_generator.bpf.o";
        printf("--- Loading DUMMY/COMBINED Generator (%s) ---\n", bpf_file_name);
    } else {
        bpf_file_name = "packet_dropper.bpf.o";
        printf("--- Loading PACKET DROPPER (%s) ---\n", bpf_file_name);
    }
    
    snprintf(bpf_obj_path, sizeof(bpf_obj_path), "%s/%s", dir_path, bpf_file_name);
    free(prog_dir);

    // Load BPF Object
    bpf_obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (libbpf_get_error(bpf_obj)) { 
        fprintf(stderr, "Error opening BPF object file: %s\n", bpf_obj_path);
        return 1; 
    }
    if (bpf_object__load(bpf_obj)) { 
        fprintf(stderr, "Error loading BPF object.\n");
        bpf_object__close(bpf_obj); 
        return 1; 
    }

    // Find Programs
    eg_prog = bpf_object__find_program_by_name(bpf_obj, "handle_egress");
    ing_prog = bpf_object__find_program_by_name(bpf_obj, "handle_ingress");

    if (!eg_prog) { fprintf(stderr, "Error: handle_egress not found\n"); return 1; }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex_g, .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
    bpf_tc_hook_create(&hook);

    // Attach Egress (Always)
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, eg_opts, .prog_fd = bpf_program__fd(eg_prog), .flags = BPF_TC_F_REPLACE);
    hook.attach_point = BPF_TC_EGRESS;
    if (bpf_tc_attach(&hook, &eg_opts)) { fprintf(stderr, "Failed to attach egress\n"); cleanup(0); return 1; }
    printf("[INFO] Attached Egress.\n");

    // Attach Ingress (Only if needed)
    // 只有 Fixed/Dynamic/Ingress/Combined 模式可能需要 Ingress 丢包
    // Dummy 模式通常只在 Egress 做 Clone
    if (ing_prog && mode != MODE_DUMMY && mode != MODE_DUMMY_DYNAMIC) {
        DECLARE_LIBBPF_OPTS(bpf_tc_opts, ing_opts, .prog_fd = bpf_program__fd(ing_prog), .flags = BPF_TC_F_REPLACE);
        hook.attach_point = BPF_TC_INGRESS;
        if (bpf_tc_attach(&hook, &ing_opts)) { fprintf(stderr, "Failed to attach ingress\n"); cleanup(0); return 1; }
        printf("[INFO] Attached Ingress.\n");
    }

    map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "state_map");
    if (map_fd < 0) { fprintf(stderr, "Error: state_map not found\n"); cleanup(0); return 1; }
    
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    // --- Main Logic Loop ---
    
    // 1. 初始化 Map 状态
    __u32 key = 0;
    struct state initial_state = {0};
    
    // 根据模式设置初始值
    if (mode == MODE_COMBINED) {
        initial_state.drop_probability = (__u32)prob;
        initial_state.dummy_probability = (__u32)dummy_prob;
        printf("Mode COMBINED: Drop %ld%%, Dummy %ld%%\n", prob, dummy_prob);
    } else if (mode == MODE_DUMMY) {
        initial_state.dummy_probability = (__u32)prob;
        printf("Mode DUMMY (Fixed): Prob %ld%%\n", prob);
    } else if (mode == MODE_FIXED || mode == MODE_INGRESS) {
        initial_state.drop_probability = (__u32)prob;
        printf("Mode DROP (Fixed/Ingress): Prob %ld%%\n", prob);
    } else {
        // Dynamic modes start at 0 and adjust
        printf("Mode DYNAMIC (%s): MaxProb %ld%%, Rate %ld-%ld PPS\n", 
               (mode == MODE_DUMMY_DYNAMIC) ? "Dummy" : "Drop", 
               max_prob, min_rate, max_rate);
    }

    bpf_map_update_elem(map_fd, &key, &initial_state, BPF_ANY);

    // 2. 循环
    if (mode == MODE_FIXED || mode == MODE_DUMMY || mode == MODE_COMBINED || mode == MODE_INGRESS) {
        while(1) sleep(10); // 静态模式，不需要动态调整
    } else {
        // 动态模式 (Dynamic Drop OR Dynamic Dummy)
        last_time_ns = get_time_ns();
        while (1) {
            sleep(UPDATE_INTERVAL_SEC);
            
            struct state current_state;
            if (bpf_map_lookup_elem(map_fd, &key, &current_state) != 0) continue;

            __u64 current_time_ns = get_time_ns();
            __u64 time_diff_ns = current_time_ns - last_time_ns;
            __u64 count_diff = current_state.packet_count - last_packet_count;
            
            last_time_ns = current_time_ns;
            last_packet_count = current_state.packet_count;

            double pps = (double)count_diff * 1e9 / time_diff_ns;
            __u32 new_prob = 0;

            if (pps > min_rate) {
                if (pps >= max_rate) new_prob = max_prob;
                else new_prob = (__u32)(((pps - min_rate) / (max_rate - min_rate)) * max_prob);
            }

            // 根据是 Drop Dynamic 还是 Dummy Dynamic 更新不同的字段
            if (mode == MODE_DUMMY_DYNAMIC) {
                current_state.dummy_probability = new_prob;
                // drop_prob 保持为 0
            } else {
                current_state.drop_probability = new_prob;
                // dummy_prob 保持为 0
            }
            
            bpf_map_update_elem(map_fd, &key, &current_state, BPF_ANY);
        }
    }

    return 0;
}
