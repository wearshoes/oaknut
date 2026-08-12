// SPDX-FileCopyrightText: Copyright (c) 2022 merryhime <https://mary.rs>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <new>
#include <type_traits>

#if defined(_WIN32)
#    define NOMINMAX
#    include <windows.h>
#elif defined(__APPLE__)
#    include <TargetConditionals.h>
#    include <libkern/OSCacheControl.h>
#    include <pthread.h>
#    include <sys/mman.h>
#    include <unistd.h>
#else
#    if defined(__ANDROID__)
#        include <dlfcn.h>
#        include <fcntl.h>
#        include <linux/ashmem.h>
#        include <sys/ioctl.h>
#        include <sys/syscall.h>
#        include <unistd.h>
#        if defined(B0)
#            undef B0
#        endif
#    endif
#    include <sys/mman.h>
#endif

namespace oaknut {

class CodeBlock {
public:
    enum class MappingMethod {
        Single,
        MemfdLibc,
        ASharedMemory,
        MemfdSyscall,
        Ashmem,
    };

    explicit CodeBlock(std::size_t size)
        : m_size(size)
    {
#if defined(_WIN32)
        m_executable_memory = (std::uint32_t*)VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        m_writable_memory = m_executable_memory;
#elif defined(__APPLE__)
#    if TARGET_OS_IPHONE
        m_executable_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
#    else
        m_executable_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
#    endif
        m_writable_memory = m_executable_memory;
#elif defined(__NetBSD__)
        m_executable_memory = (std::uint32_t*)mmap(nullptr, size, PROT_MPROTECT(PROT_READ | PROT_WRITE | PROT_EXEC), MAP_ANON | MAP_PRIVATE, -1, 0);
        m_writable_memory = m_executable_memory;
#elif defined(__OpenBSD__)
        m_executable_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
        m_writable_memory = m_executable_memory;
#elif defined(__ANDROID__)
        m_fd = CreateAndroidSharedMemory(size);
        if (m_fd < 0)
            throw std::bad_alloc{};

        m_writable_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, m_fd, 0);
        m_executable_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_SHARED, m_fd, 0);
#else
        m_executable_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
        m_writable_memory = m_executable_memory;
#endif

#if defined(_WIN32)
        if (m_executable_memory == nullptr)
#else
        if (m_executable_memory == MAP_FAILED || m_writable_memory == MAP_FAILED)
#endif
        {
#if defined(__ANDROID__)
            if (m_executable_memory != MAP_FAILED)
                munmap(m_executable_memory, m_size);
            if (m_writable_memory != MAP_FAILED)
                munmap(m_writable_memory, m_size);
            close(m_fd);
            m_fd = -1;
#endif
            m_executable_memory = nullptr;
            m_writable_memory = nullptr;
            throw std::bad_alloc{};
        }
    }

    ~CodeBlock()
    {
        if (m_executable_memory == nullptr)
            return;

#if defined(_WIN32)
        VirtualFree((void*)m_executable_memory, 0, MEM_RELEASE);
#else
        munmap(m_executable_memory, m_size);
#    if defined(__ANDROID__)
        munmap(m_writable_memory, m_size);
        close(m_fd);
#    endif
#endif
    }

    CodeBlock(const CodeBlock&) = delete;
    CodeBlock& operator=(const CodeBlock&) = delete;
    CodeBlock(CodeBlock&&) = delete;
    CodeBlock& operator=(CodeBlock&&) = delete;

    std::uint32_t* ptr() const
    {
        return m_writable_memory;
    }

    template<typename T>
    T xptr() const
    {
        static_assert(std::is_pointer_v<T> || std::is_same_v<T, std::uintptr_t> || std::is_same_v<T, std::intptr_t>);
        return reinterpret_cast<T>(m_executable_memory);
    }

    MappingMethod mapping_method() const
    {
        return m_mapping_method;
    }

    const char* mapping_method_name() const
    {
        switch (m_mapping_method) {
        case MappingMethod::Single:
            return "single";
        case MappingMethod::MemfdLibc:
            return "memfd-libc";
        case MappingMethod::ASharedMemory:
            return "asharedmemory";
        case MappingMethod::MemfdSyscall:
            return "memfd-syscall";
        case MappingMethod::Ashmem:
            return "ashmem";
        }
        return "unknown";
    }

    void protect()
    {
#if defined(__APPLE__) && !TARGET_OS_IPHONE
        pthread_jit_write_protect_np(1);
#elif defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
        mprotect(m_executable_memory, m_size, PROT_READ | PROT_EXEC);
#endif
    }

    void unprotect()
    {
#if defined(__APPLE__) && !TARGET_OS_IPHONE
        pthread_jit_write_protect_np(0);
#elif defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
        mprotect(m_executable_memory, m_size, PROT_READ | PROT_WRITE);
#endif
    }

    void invalidate(std::uint32_t* executable_memory, std::size_t size)
    {
#if defined(__APPLE__)
        sys_icache_invalidate(executable_memory, size);
#elif defined(_WIN32)
        FlushInstructionCache(GetCurrentProcess(), executable_memory, size);
#else
        static std::size_t icache_line_size = 0x10000, dcache_line_size = 0x10000;

        std::uint64_t ctr;
        __asm__ volatile("mrs %0, ctr_el0"
                         : "=r"(ctr));

        const std::size_t isize = icache_line_size = std::min<std::size_t>(icache_line_size, 4 << ((ctr >> 0) & 0xf));
        const std::size_t dsize = dcache_line_size = std::min<std::size_t>(dcache_line_size, 4 << ((ctr >> 16) & 0xf));

        const std::uintptr_t executable_start = reinterpret_cast<std::uintptr_t>(executable_memory);
        const std::uintptr_t executable_base = reinterpret_cast<std::uintptr_t>(m_executable_memory);
        const std::uintptr_t writable_start = reinterpret_cast<std::uintptr_t>(m_writable_memory) + (executable_start - executable_base);
        const std::uintptr_t writable_end = writable_start + size;
        const std::uintptr_t executable_end = executable_start + size;

        for (std::uintptr_t addr = writable_start & ~(dsize - 1); addr < writable_end; addr += dsize) {
            __asm__ volatile("dc cvau, %0"
                             :
                             : "r"(addr)
                             : "memory");
        }
        __asm__ volatile("dsb ish\n"
                         :
                         :
                         : "memory");

        for (std::uintptr_t addr = executable_start & ~(isize - 1); addr < executable_end; addr += isize) {
            __asm__ volatile("ic ivau, %0"
                             :
                             : "r"(addr)
                             : "memory");
        }
        __asm__ volatile("dsb ish\nisb\n"
                         :
                         :
                         : "memory");
#endif
    }

    void invalidate_all()
    {
        invalidate(m_executable_memory, m_size);
    }

protected:
#if defined(__ANDROID__)
    using SharedMemoryCreate = int (*)(const char*, std::size_t);

    int CreateAndroidSharedMemory(std::size_t size)
    {
        if (void* symbol = dlsym(RTLD_DEFAULT, "memfd_create")) {
            const auto create = reinterpret_cast<int (*)(const char*, unsigned int)>(symbol);
            const int fd = create("oaknut-code-cache", 0);
            if (fd >= 0 && ftruncate(fd, static_cast<off_t>(size)) == 0) {
                m_mapping_method = MappingMethod::MemfdLibc;
                return fd;
            }
            if (fd >= 0)
                close(fd);
        }

        void* libandroid = dlopen("libandroid.so", RTLD_NOW | RTLD_LOCAL);
        if (libandroid != nullptr) {
            const auto create = reinterpret_cast<SharedMemoryCreate>(dlsym(libandroid, "ASharedMemory_create"));
            if (create != nullptr) {
                const int fd = create("oaknut-code-cache", size);
                dlclose(libandroid);
                if (fd >= 0) {
                    m_mapping_method = MappingMethod::ASharedMemory;
                    return fd;
                }
            } else {
                dlclose(libandroid);
            }
        }

#    if defined(SYS_memfd_create)
        {
            const int fd = static_cast<int>(syscall(SYS_memfd_create, "oaknut-code-cache", 0));
            if (fd >= 0 && ftruncate(fd, static_cast<off_t>(size)) == 0) {
                m_mapping_method = MappingMethod::MemfdSyscall;
                return fd;
            }
            if (fd >= 0)
                close(fd);
        }
#    endif

        const int fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
        if (fd < 0)
            return -1;

        const char name[] = "oaknut-code-cache";
        if (ioctl(fd, ASHMEM_SET_NAME, name) != 0 || ioctl(fd, ASHMEM_SET_SIZE, size) != 0 ||
            ioctl(fd, ASHMEM_SET_PROT_MASK, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            close(fd);
            return -1;
        }

        m_mapping_method = MappingMethod::Ashmem;
        return fd;
    }
#endif

    std::uint32_t* m_writable_memory = nullptr;
    std::uint32_t* m_executable_memory = nullptr;
    std::size_t m_size = 0;
    MappingMethod m_mapping_method = MappingMethod::Single;
#if defined(__ANDROID__)
    int m_fd = -1;
#endif
};

}  // namespace oaknut
