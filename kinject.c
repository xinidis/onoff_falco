#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/ctype.h>

static bool enable_write = false;
module_param(enable_write, bool, 0644);
MODULE_PARM_DESC(enable_write, "Enable write (true/false)");

static bool enable_exit_hook = true;
module_param(enable_exit_hook, bool, 0644);
MODULE_PARM_DESC(enable_exit_hook, "Enable exit hook (true/false)");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void (*text_poke_t)(void *addr, const void *opcode, size_t len);

#define LIVE_ADDR(addr) ((addr) + kaslr_offset)

typedef struct patch {
    u64 addr;
    const char *buf;
} patch_t;

static text_poke_t text_poke_fn;

u64 kallsyms_lookup_name_base = 0xffffffff8122cfd0;
u64 kaslr_offset;

patch_t patches_exit_hook_on[] = {
    {
        // ffffffff811eda90 <syscall_exit_work>:
        // ...
        // ffffffff811edb53: 66 90  xchg   %ax,%ax
        // ffffffff811edb55: eb 82  jmp    ffffffff811edad9 <syscall_exit_work+0x49>
        .addr = 0xffffffff811f31f3,
        .buf = "eb 02",  // jump +4
    },
    {
        // ffffffff8221dc00 <__SCT__tp_func_sys_exit>:
        // ffffffff8221dc00: e9 1b f8 fc fe  jmp ffffffff811ed420 <__traceiter_sys_exit>
        // ffffffff8221dc05: 0f b9 cc        ud1 %esp,%ecx
        .addr = 0xffffffff82250700,
        .buf = "e9 7b 27 fa fe",  // jmp ffffffff811ed420 <__traceiter_sys_exit>
    },
    {
        // ffffffff811eda90 <syscall_exit_work>:
	// ...
        // ffffffff811edb88: e8 73 00 03 01  call ffffffff8221dc00 <__SCT__tp_func_sys_exit>
        .addr = 0xffffffff811f3228,
        .buf = "e8 53 fc ff ff", // call ffffffff8221dc00 <__SCT__tp_func_sys_exit>
    },
};
int patches_exit_hook_on_len = sizeof(patches_exit_hook_on) / sizeof(patch_t);

patch_t patches_exit_hook_off[] = {
    {
        // ffffffff811eda90 <syscall_exit_work>:
        // ...
        // ffffffff811edb53: 66 90  xchg   %ax,%ax
        // ffffffff811edb55: eb 82  jmp    ffffffff811edad9 <syscall_exit_work+0x49>
        .addr = 0xffffffff811f31f3,
        .buf = "66 90",  // nop
    },
    {
        // ffffffff8221dc00 <__SCT__tp_func_sys_exit>:
        // ffffffff8221dc00: e9 1b f8 fc fe  jmp ffffffff811ed420 <__traceiter_sys_exit>
        // ffffffff8221dc05: 0f b9 cc        ud1 %esp,%ecx
        .addr = 0xffffffff82250700,
        .buf = "e9 bb 23 fa fe",  // jmp ffffffff811ed420 <__traceiter_sys_exit>
    },
    {
        // ffffffff811eda90 <syscall_exit_work>:
	// ...
        // ffffffff811edb88: e8 73 00 03 01  call ffffffff8221dc00 <__SCT__tp_func_sys_exit>
        .addr = 0xffffffff811f3228,
        .buf = "e8 93 f8 ff ff", // call ffffffff811ed420 <__traceiter_sys_exit>
        //.buf = "90 90 90 90 90", // nop 
    },
};
int patches_exit_hook_off_len = sizeof(patches_exit_hook_off) / sizeof(patch_t);

static int hex_char_to_val(char c)
{
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex_byte(const char *s, u8 *out)
{
    int hi = hex_char_to_val(s[0]);
    int lo = hex_char_to_val(s[1]);
    if (hi < 0 || lo < 0) return -EINVAL;
    *out = (hi << 4) | lo;
    //pr_info("%02x", *out);
    return 0;
}

static size_t hex_string_to_bytes(const char *hex_str, u8 *out, size_t max_len)
{
    size_t count = 0;
    while (*hex_str && count < max_len) {
        while (*hex_str == ' ') hex_str++; // Skip spaces
        if (!isxdigit(hex_str[0]) || !isxdigit(hex_str[1]))
            break;

        if (parse_hex_byte(hex_str, &out[count]) < 0)
            break;

        count++;
        hex_str += 2;
    }
    return count;
}

static void *get_symbol_address(const char *symbol_name) {
    static kallsyms_lookup_name_t kallsyms_lookup_name_fn;
    if (!kallsyms_lookup_name_fn) {
        struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

        // Register kprobe to locate the symbol
        if (register_kprobe(&kp) < 0) {
            pr_err("Failed to register kprobe for symbol: %s\n", kp.symbol_name);
            return NULL;
        }
        // Retrieve the address
        unregister_kprobe(&kp);

        if (!kp.addr) {
            pr_err("Symbol %s not found\n", kp.symbol_name);
            return NULL;
        }

        kallsyms_lookup_name_fn = (kallsyms_lookup_name_t)kp.addr;
	kaslr_offset = (u64)kp.addr - kallsyms_lookup_name_base;
        pr_info("Address of %s: %llx, kaslr offset: 0x%llx\n", kp.symbol_name, (u64)kp.addr, kaslr_offset);
    }

    u64 addr = kallsyms_lookup_name_fn(symbol_name);
    pr_info("%s: %llx\n", symbol_name, addr);
    return (void *)addr;
}

static void read_mem(unsigned long addr) {
    unsigned char buffer[16]; // Temporary buffer to store read bytes
    int i;
    int num_bytes = sizeof(buffer);

    addr &= ~(unsigned long)0xf;
    //pr_info("Reading %d bytes from address 0x%lx\n", num_bytes, addr);

    for (i = 0; i < num_bytes; i++) {
        if (copy_from_kernel_nofault(&buffer[i], (void *)(addr + i), 1)) {
            pr_err("Failed to read memory at address 0x%lx\n", addr + i);
            break;
        }
    }

    //pr_info("Memory content: ");

    for (i = 0; i < num_bytes; i++) {
        if (i % 16 == 0) {
            pr_info("%lx: ", addr + i);
        }
        pr_cont("%02x ", buffer[i]);
    }
    pr_cont("\n");
}

static void handle_patch(patch_t *patch, bool to_write) {

    read_mem(LIVE_ADDR(patch->addr));

    if (to_write) {
        u8 buf[16];
        size_t buf_len = hex_string_to_bytes(patch->buf, buf, sizeof(buf));
	    //pr_info("buf_len: %zu\n", buf_len);

        //mutex_lock(text_mutex);
        text_poke_fn((void *)LIVE_ADDR(patch->addr), buf, buf_len);
        //mutex_unlock(text_mutex);
        read_mem(LIVE_ADDR(patch->addr));
    }
}

static int __init kinject_init(void) {
    void *addr;
    u64 patch_addr;

    addr = get_symbol_address("text_poke");
    if (!addr) {
        return -EFAULT;
    }
    text_poke_fn = (text_poke_t)addr;

    addr = get_symbol_address("text_mutex");
    if (!addr) {
        return -EFAULT;
    }
    struct mutex *text_mutex = (struct mutex *)addr;

    patch_t *patches;
    
    patches = enable_exit_hook ? patches_exit_hook_on : patches_exit_hook_off;
    int patches_len = enable_exit_hook ? patches_exit_hook_on_len : patches_exit_hook_off_len;

    for (int i = 0; i < patches_len; i++) {
        handle_patch(&patches[i], enable_write);
    }

    return 0;
}

static void __exit kinject_exit(void) {
    pr_info("kinject exiting\n");
}

module_init(kinject_init);
module_exit(kinject_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Someone");
MODULE_DESCRIPTION("Kernel module to inject a patch into the kernel");
