/**
 * KernelSU 文件描述符注入测试程序
 * 
 * 使用方法：
 * 1. 编译：gcc -o ksu_fd_inject ksu_fd_inject.c
 * 2. 运行：./ksu_fd_inject
 * 
 * 注意：需要 root 权限或 KernelSU 管理器权限
 */

//#define _GNU_SOURCE
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <unistd.h>
//#include <fcntl.h>
//#include <errno.h>
//#include <sys/reboot.h>
//#include <sys/ioctl.h>
//#include <sys/syscall.h>
//#include <linux/reboot.h>

// KernelSU 魔法数字定义
#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define KSU_INSTALL_MAGIC2 0xCAFEBABE

// KernelSU IOCTL 命令定义
#define KSU_IOCTL_GET_INFO _IOC(_IOC_READ, 'K', 2, 0)
#define KSU_IOCTL_GET_MANAGER_APPID _IOC(_IOC_READ, 'K', 10, 0)
#define KSU_IOCTL_GRANT_ROOT _IOC(_IOC_NONE, 'K', 1, 0)
#define KSU_IOCTL_CHECK_SAFEMODE _IOC(_IOC_READ, 'K', 5, 0)

// 内核信息结构体
struct ksu_get_info_cmd {
    uint32_t version;   // KernelSU 版本
    uint32_t flags;     // 标志位
    uint32_t features;  // 支持的最大功能ID
};

// 管理器 appid 结构体
struct ksu_get_manager_appid_cmd {
    uint32_t appid;     // 管理器 appid
};

// 安全模式结构体
struct ksu_check_safemode_cmd {
    uint8_t in_safe_mode; // 是否处于安全模式
};

/**
 * 尝试通过 reboot 系统调用注入 KernelSU 文件描述符
 * 
 * @return 成功返回文件描述符，失败返回 -1
 */
int try_inject_ksu_fd() {
    int ksu_fd = -1;
    
    printf("[*] 尝试通过 reboot 系统调用注入 KernelSU 文件描述符...\n");
    
    // 调用 reboot 系统调用，使用 KernelSU 的魔法数字
    long result = syscall(__NR_reboot, 
                         KSU_INSTALL_MAGIC1,  // magic1
                         KSU_INSTALL_MAGIC2,  // magic2
                         0,                   // cmd (设为0)
                         &ksu_fd);            // 用于接收文件描述符
    
    if (result < 0) {
        printf("[-] reboot 系统调用失败: %s\n", strerror(errno));
        return -1;
    }
    
    if (ksu_fd >= 0) {
        printf("[+] 成功获取 KernelSU 文件描述符: fd=%d\n", ksu_fd);
    } else {
        printf("[-] 未能获取文件描述符 (可能设备未安装 KernelSU 或没有权限)\n");
    }
    
    return ksu_fd;
}

/**
 * 通过扫描 /proc/self/fd 查找 [ksu_driver]
 * 
 * @return 成功返回文件描述符，失败返回 -1
 */
int scan_for_ksu_driver() {
    char fd_path[64];
    char target[1024];
    
    printf("[*] 扫描 /proc/self/fd 查找 [ksu_driver]...\n");
    
    // 扫描当前进程的所有文件描述符
    for (int fd = 0; fd < 1024; fd++) {
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        
        ssize_t n = readlink(fd_path, target, sizeof(target) - 1);
        if (n > 0) {
            target[n] = '\0';
            if (strstr(target, "[ksu_driver]")) {
                printf("[+] 找到 [ksu_driver]: fd=%d -> %s\n", fd, target);
                return fd;
            }
        }
    }
    
    printf("[-] 未找到 [ksu_driver]\n");
    return -1;
}

/**
 * 通过 ioctl 获取 KernelSU 信息
 */
void get_ksu_info(int fd) {
    if (fd < 0) {
        printf("[-] 无效的文件描述符\n");
        return;
    }
    
    struct ksu_get_info_cmd info = {0};
    
    printf("[*] 获取 KernelSU 信息...\n");
    
    int ret = ioctl(fd, KSU_IOCTL_GET_INFO, &info);
    if (ret < 0) {
        printf("[-] GET_INFO ioctl 失败: %s\n", strerror(errno));
        return;
    }
    
    printf("[+] KernelSU 信息:\n");
    printf("    版本: 0x%08x\n", info.version);
    printf("    标志: 0x%08x\n", info.flags);
    printf("    功能: 0x%08x\n", info.features);
    
    // 解析标志位
    printf("    解析标志位:\n");
    if (info.flags & 0x1) {
        printf("        - LKM 模式 (可加载内核模块)\n");
    }
    if (info.flags & 0x2) {
        printf("        - 当前进程是管理器\n");
    }
}

/**
 * 检查安全模式
 */
void check_safe_mode(int fd) {
    if (fd < 0) {
        return;
    }
    
    struct ksu_check_safemode_cmd cmd = {0};
    
    printf("[*] 检查安全模式...\n");
    
    int ret = ioctl(fd, KSU_IOCTL_CHECK_SAFEMODE, &cmd);
    if (ret < 0) {
        printf("[-] CHECK_SAFEMODE ioctl 失败: %s\n", strerror(errno));
        return;
    }
    
    printf("[+] 安全模式: %s\n", cmd.in_safe_mode ? "是" : "否");
}

/**
 * 获取管理器 appid
 */
void get_manager_appid(int fd) {
    if (fd < 0) {
        return;
    }
    
    struct ksu_get_manager_appid_cmd cmd = {0};
    
    printf("[*] 获取管理器 appid...\n");
    
    int ret = ioctl(fd, KSU_IOCTL_GET_MANAGER_APPID, &cmd);
    if (ret < 0) {
        printf("[-] GET_MANAGER_APPID ioctl 失败: %s\n", strerror(errno));
        return;
    }
    
    printf("[+] 管理器 appid: %u\n", cmd.appid);
    printf("[+] 当前进程 UID: %d\n", getuid());
    
    if (cmd.appid == (getuid() % 100000)) {
        printf("[+] 当前进程是管理器！\n");
    } else {
        printf("[-] 当前进程不是管理器\n");
    }
}

/**
 * 测试授予 root 权限
 */
void test_grant_root(int fd) {
    if (fd < 0) {
        return;
    }
    
    printf("[*] 测试授予 root 权限...\n");
    
    int ret = ioctl(fd, KSU_IOCTL_GRANT_ROOT, NULL);
    if (ret < 0) {
        printf("[-] GRANT_ROOT 失败: %s (可能没有权限)\n", strerror(errno));
        return;
    }
    
    printf("[+] GRANT_ROOT 成功！\n");
    printf("[+] 当前 UID: %d\n", getuid());
    
    if (getuid() == 0) {
        printf("[+] 当前进程已获得 root 权限！\n");
    }
}

/**
 * 检查设备是否安装了 KernelSU
 */
int check_ksu_installed() {
    printf("[*] 检查 KernelSU 安装状态...\n");
    
    // 方法1: 检查内核模块
    if (access("/sys/module/kernelsu", F_OK) == 0) {
        printf("[+] KernelSU 内核模块已加载\n");
        return 1;
    }
    
    // 方法2: 检查设备文件
    if (access("/dev/kernelsu", F_OK) == 0) {
        printf("[+] 找到 /dev/kernelsu 设备文件\n");
        return 1;
    }
    
    // 方法3: 检查 kallsyms
    FILE *fp = popen("cat /proc/kallsyms 2>/dev/null | grep kernelsu | head -1", "r");
    if (fp) {
        char buf[256];
        if (fgets(buf, sizeof(buf), fp) != NULL) {
            printf("[+] 在 kallsyms 中找到 KernelSU 符号\n");
            pclose(fp);
            return 1;
        }
        pclose(fp);
    }
    
    printf("[-] 未检测到 KernelSU 安装\n");
    return 0;
}

int main(int argc, char *argv[]) {
    printf("========================================\n");
    printf("KernelSU 文件描述符注入测试程序\n");
    printf("========================================\n\n");
    
    // 检查当前用户权限
    uid_t uid = getuid();
    printf("[*] 当前用户 UID: %d\n", uid);
    
    if (uid != 0) {
        printf("[!] 警告：当前用户不是 root，某些操作可能需要 root 权限\n");
    }
    
    // 检查 KernelSU 是否安装
    if (!check_ksu_installed()) {
        printf("[-] 可能未安装 KernelSU，继续测试...\n");
    }
    
    int ksu_fd = -1;
    
    // 方法1: 尝试注入文件描述符
    printf("\n[方法1] 尝试注入文件描述符\n");
    ksu_fd = try_inject_ksu_fd();
    
    // 方法2: 如果注入失败，尝试扫描现有文件描述符
    if (ksu_fd < 0) {
        printf("\n[方法2] 扫描现有文件描述符\n");
        ksu_fd = scan_for_ksu_driver();
    }
    
    // 如果有有效的文件描述符，测试功能
    if (ksu_fd >= 0) {
        printf("\n[*] 测试 KernelSU 功能...\n");
        
        // 获取 KernelSU 信息
        get_ksu_info(ksu_fd);
        
        // 检查安全模式
        check_safe_mode(ksu_fd);
        
        // 获取管理器 appid
        get_manager_appid(ksu_fd);
        
        // 测试授予 root 权限
        test_grant_root(ksu_fd);
        
        // 关闭文件描述符
        close(ksu_fd);
        printf("[*] 已关闭文件描述符\n");
    } else {
        printf("\n[-] 未能获取 KernelSU 文件描述符\n");
        printf("    可能的原因：\n");
        printf("    1. 设备未安装 KernelSU\n");
        printf("    2. 当前进程没有足够权限\n");
        printf("    3. KernelSU 未运行或未正确加载\n");
    }
    
    printf("\n[*] 测试完成\n");
    return 0;
}