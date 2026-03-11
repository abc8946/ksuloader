#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/reboot.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <stdint.h>
// 定义魔法数字（从内核代码中提取）
#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define KSU_INSTALL_MAGIC2 0xC001D00D

// KernelSU IOCTL 命令定义（从 ksu.h 中提取）
#define KSU_IOCTL_GET_INFO _IOC(_IOC_READ, 'K', 2, 0)
#define KSU_IOCTL_GET_MANAGER_APPID _IOC(_IOC_READ, 'K', 10, 0)
#define KSU_IOCTL_CHECK_SAFEMODE _IOC(_IOC_READ, 'K', 5, 0)

// 内核信息结构
struct ksu_get_info_cmd {
    uint32_t version;
    uint32_t flags;
    uint32_t features;
};

// 管理器 appid 结构
struct ksu_get_manager_appid_cmd {
    uint32_t appid;
};

// 安全模式检查结构
struct ksu_check_safemode_cmd {
    uint8_t in_safe_mode;
};

// 打印二进制表示
void print_binary(uint32_t num) {
    for (int i = 31; i >= 0; i--) {
        printf("%d", (num >> i) & 1);
        if (i % 8 == 0 && i != 0) printf(" ");
    }
    printf("\n");
}

// 测试注入的文件描述符
int test_ksu_fd(int ksu_fd) {
    printf("\n[测试 KSU 文件描述符]\n");
    printf("KSU FD: %d\n", ksu_fd);
    
    // 1. 测试 GET_INFO 命令
    printf("\n1. 测试 GET_INFO 命令:\n");
    struct ksu_get_info_cmd info_cmd = {0};
    
    int ret = ioctl(ksu_fd, KSU_IOCTL_GET_INFO, &info_cmd);
    if (ret < 0) {
        printf("   GET_INFO 失败: %s\n", strerror(errno));
        return -1;
    }
    
    printf("   版本: %u (0x%08x)\n", info_cmd.version, info_cmd.version);
    printf("   标志: %u (0x%08x)\n", info_cmd.flags, info_cmd.flags);
    printf("   标志位: ");
    print_binary(info_cmd.flags);
    printf("   功能: %u\n", info_cmd.features);
    
    // 解析标志位
    if (info_cmd.flags & 0x1) {
        printf("   ✓ LKM 模式 (可加载内核模块)\n");
    } else {
        printf("   - 非 LKM 模式\n");
    }
    
    if (info_cmd.flags & 0x2) {
        printf("   ✓ 当前进程是管理器\n");
    } else {
        printf("   - 当前进程不是管理器\n");
    }
    
    // 2. 测试 GET_MANAGER_APPID 命令
    printf("\n2. 测试 GET_MANAGER_APPID 命令:\n");
    struct ksu_get_manager_appid_cmd mgr_cmd = {0};
    
    ret = ioctl(ksu_fd, KSU_IOCTL_GET_MANAGER_APPID, &mgr_cmd);
    if (ret < 0) {
        printf("   GET_MANAGER_APPID 失败: %s\n", strerror(errno));
    } else {
        printf("   管理器 appid: %u\n", mgr_cmd.appid);
        printf("   当前进程 UID: %u\n", getuid());
        printf("   当前进程 EUID: %u\n", geteuid());
        
        if (mgr_cmd.appid == getuid() % 100000) {  // PER_USER_RANGE
            printf("   ✓ 当前进程可能是管理器\n");
        } else {
            printf("   - 当前进程不是管理器\n");
        }
    }
    
    // 3. 测试安全模式
    printf("\n3. 测试 CHECK_SAFEMODE 命令:\n");
    struct ksu_check_safemode_cmd safe_cmd = {0};
    
    ret = ioctl(ksu_fd, KSU_IOCTL_CHECK_SAFEMODE, &safe_cmd);
    if (ret < 0) {
        printf("   CHECK_SAFEMODE 失败: %s\n", strerror(errno));
    } else {
        printf("   安全模式状态: %s\n", safe_cmd.in_safe_mode ? "是" : "否");
    }
    
    return 0;
}

// 检查是否已经有 KSU 文件描述符
int find_existing_ksu_fd() {
    printf("[扫描现有文件描述符]\n");
    
    char path[64];
    char target[1024];
    int found_fd = -1;
    
    for (int fd = 0; fd < 1024; fd++) {
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        
        ssize_t len = readlink(path, target, sizeof(target) - 1);
        if (len < 0) continue;
        
        target[len] = '\0';
        
        if (strstr(target, "[ksu_driver]")) {
            printf("   在 fd=%d 找到 [ksu_driver]: %s\n", fd, target);
            found_fd = fd;
        } else if (strstr(target, "[ksu_fdwrapper]")) {
            printf("   在 fd=%d 找到 [ksu_fdwrapper]: %s\n", fd, target);
        }
    }
    
    return found_fd;
}

int main() {
    printf("========================================\n");
    printf("KernelSU 文件描述符注入测试程序\n");
    printf("========================================\n");
    
    // 检查当前用户权限
    uid_t uid = getuid();
    uid_t euid = geteuid();
    printf("当前进程信息:\n");
    printf("  PID: %d\n", getpid());
    printf("  UID: %d\n", uid);
    printf("  EUID: %d\n", euid);
    printf("  权限: %s\n", (uid == 0 || euid == 0) ? "root" : "普通用户");
    
    // 首先检查是否已经有 KSU 文件描述符
    int existing_fd = find_existing_ksu_fd();
    if (existing_fd >= 0) {
        printf("\n[已存在 KSU 文件描述符，直接测试]\n");
        return test_ksu_fd(existing_fd);
    }
    
    printf("\n[准备调用特殊 reboot 系统调用]\n");
    printf("魔法数字 1: 0x%08x (%u)\n", KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC1);
    printf("魔法数字 2: 0x%08x (%u)\n", KSU_INSTALL_MAGIC2, KSU_INSTALL_MAGIC2);
    
    // 准备接收文件描述符的变量
    int ksu_fd = -1;
    
    // 方法1: 使用 syscall 直接调用
    printf("\n方法1: 使用 syscall(__NR_reboot, ...)\n");
    
    // 注意: 不同的架构可能有不同的系统调用号
    // 我们可以尝试多种方法
    
#if defined(__x86_64__)
    #define REBOOT_NR 169
#elif defined(__i386__)
    #define REBOOT_NR 88
#elif defined(__aarch64__)
    #define REBOOT_NR 142
#elif defined(__arm__)
    #define REBOOT_NR 88
#else
    #define REBOOT_NR 169  // 默认猜测
#endif
    
    printf("尝试系统调用号: %d\n", REBOOT_NR);
    
    long result = syscall(REBOOT_NR, 
                         (long)KSU_INSTALL_MAGIC1,
                         (long)KSU_INSTALL_MAGIC2,
                         (long)0,  // cmd
                         (void*)&ksu_fd);
    
    printf("syscall 返回值: %ld\n", result);
    printf("errno: %d (%s)\n", errno, strerror(errno));
    
    if (result < 0 && errno == EINVAL) {
        printf("可能是系统调用号不正确，尝试其他方法...\n");
        
        // 方法2: 使用库函数 reboot
        printf("\n方法2: 使用 reboot() 库函数\n");
        
        // 注意: 标准的 reboot 函数可能不支持4个参数
        // 我们尝试使用 syscall 的不同变体
        
        // 尝试常用的 reboot 系统调用号
        int reboot_nums[] = {169, 88, 142, 0};
        
        for (int i = 0; i < sizeof(reboot_nums)/sizeof(reboot_nums[0]); i++) {
            if (reboot_nums[i] == 0) break;
            
            printf("尝试 reboot 系统调用号: %d\n", reboot_nums[i]);
            
            ksu_fd = -1;
            result = syscall(reboot_nums[i],
                           KSU_INSTALL_MAGIC1,
                           KSU_INSTALL_MAGIC2,
                           0,
                           &ksu_fd);
            
            if (result == 0 || errno != EINVAL) {
                printf("  结果: result=%ld, errno=%d (%s), ksu_fd=%d\n",
                       result, errno, strerror(errno), ksu_fd);
                
                if (ksu_fd > 0) {
                    printf("  ✓ 成功获取 KSU 文件描述符: %d\n", ksu_fd);
                    break;
                }
            }
            
            // 休眠一下避免太快
            usleep(10000);
        }
    } else if (ksu_fd > 0) {
        printf("  ✓ 成功获取 KSU 文件描述符: %d\n", ksu_fd);
    }
    
    // 检查是否成功获取文件描述符
    if (ksu_fd <= 0) {
        printf("\n[警告] 未能通过 reboot 调用获取 KSU 文件描述符\n");
        printf("可能的原因:\n");
        printf("1. 内核中没有加载 KernelSU 模块\n");
        printf("2. 魔法数字不正确\n");
        printf("3. 当前进程没有权限\n");
        printf("4. KernelSU 版本不匹配\n");
        
        // 再次检查是否已经有了
        existing_fd = find_existing_ksu_fd();
        if (existing_fd >= 0) {
            printf("\n但通过扫描找到了现有文件描述符: %d\n", existing_fd);
            ksu_fd = existing_fd;
        } else {
            return 1;
        }
    }
    
    // 测试文件描述符
    printf("\n[开始测试 KSU 功能]\n");
    int ret = test_ksu_fd(ksu_fd);
    
    if (ret == 0) {
        printf("\n========================================\n");
        printf("测试完成！KernelSU 文件描述符工作正常\n");
        printf("========================================\n");
    } else {
        printf("\n========================================\n");
        printf("测试失败！某些功能不可用\n");
        printf("========================================\n");
    }
    
    return ret;
}
