// Included at the END of Global.cpp only in an isolated x86 test build.
// No copied allocator bodies, OS stubs, live-state reset, or fake addresses.
#if !defined(_WIN32) || defined(_M_X64) || defined(__x86_64__)
#error Allocator boundary acceptance requires native Windows x86
#endif
#include <cstdio>
static_assert(sizeof(void*) == 4);
namespace {
[[noreturn]] void BoundsFail(const char* why, unsigned code = 1)
{
    std::fprintf(stderr, "%s: %s\n", code == 77 ? "BLOCKED" : "FAIL", why);
    std::fflush(stdout);
    std::fflush(stderr);
    ::ExitProcess(code); // Each CTest invocation is an isolated process.
}
void BoundsCheck(bool ok, const char* why) { if (!ok) BoundsFail(why); }
void BoundsSmoke()
{
    for (unsigned size : {1u, 40u, 16384u, 16385u, 65536u}) {
        auto* p = static_cast<unsigned char*>(malloc_0(size));
        BoundsCheck(p != nullptr && msize(p) >= size, "public malloc/size");
        std::memset(p, 0xA7, size);
        auto* q = static_cast<unsigned char*>(realloc_0(p, size * 2));
        BoundsCheck(q != nullptr && msize(q) >= size * 2, "public realloc/size");
        for (unsigned i = 0; i < size; ++i) BoundsCheck(q[i] == 0xA7, "realloc preservation");
        free_0(q);
    }
}
DWORD WINAPI BoundsThread(void*) { for (unsigned i=0; i<16; ++i) BoundsSmoke(); return 0; }
// Bounded 64 KiB probes only. Never fill lower address space to force an address.
std::uint8_t* BoundsReserve(std::uintptr_t first, unsigned bytes)
{
    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    BoundsCheck(si.dwAllocationGranularity == 65536 && si.dwPageSize == 4096, "Windows geometry");
    const auto limit = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
    for (unsigned i=0; i<64; ++i) {
        const auto address = static_cast<std::uint64_t>(first) + i * 65536ull;
        if (address + bytes - 1 > limit) break;
        auto* p = static_cast<std::uint8_t*>(::VirtualAlloc(
            reinterpret_cast<void*>(static_cast<std::uintptr_t>(address)), bytes,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (p != nullptr) {
            MEMORY_BASIC_INFORMATION info{};
            BoundsCheck(::VirtualQuery(p, &info, sizeof(info)) == sizeof(info), "VirtualQuery");
            BoundsCheck(info.AllocationBase == p && info.State == MEM_COMMIT, "real reservation");
            return p;
        }
    }
    BoundsFail("required bounded virtual-address range unavailable", 77);
}
HeapRecord* BoundsRecord(void* address, unsigned pages, void* reservation)
{
    auto* record = reinterpret_cast<HeapRecord*>(AllocateInSmallBlock(kHeapRecordSizeBytes, true));
    BoundsCheck(record != nullptr, "production descriptor allocation");
    return ConstructHeapRecord(record, address, pages, kRecordTagLargeAllocation, reservation, 0);
}
void BoundsDispose(HeapRecord* record)
{
    (void)PopHeapRecord(record);
    SetPageOwnerRange(record->allocation, record->sizePages, nullptr);
    (void)PushHeapBlock(reinterpret_cast<SmallBlockNode*>(record),
                        static_cast<std::int32_t>(GetSmallBlockIndex(kHeapRecordSizeBytes)));
}
void BoundsMerge(std::uintptr_t first, bool releaseLeftFirst)
{
    auto* p = BoundsReserve(first, 65536);
    std::printf("reservation=%p bytes=65536 order=%s\n", p, releaseLeftFirst ? "left-first" : "right-first");
    ::EnterCriticalSection(&gAllocatorSentinel);
    // Real writable pages and descriptors allocated by the production allocator.
    auto* left = BoundsRecord(p, 1, p);
    auto* right = BoundsRecord(p + 4096, 1, p);
    p[0] = 1; p[4096] = 2;
    HeapRecord* survivor = releaseLeftFirst ? right : left;
    (void)ReleaseHeapRecord(releaseLeftFirst ? left : right);
    (void)ReleaseHeapRecord(survivor);
    BoundsCheck(survivor->allocation == p && survivor->sizePages == 2, "adjacent same-reservation merge");
    BoundsCheck(GetPageOwner(p) == survivor && GetPageOwner(p + 4096) == survivor, "merged ownership");
    BoundsCheck(survivor->next != nullptr && *survivor->next == survivor, "free bucket linkage");
    MEMORY_BASIC_INFORMATION info{};
    BoundsCheck(::VirtualQuery(p, &info, sizeof(info)) == sizeof(info) && info.State == MEM_RESERVE,
                "production release decommitted pages");
    BoundsDispose(survivor);
    ::LeaveCriticalSection(&gAllocatorSentinel);
    BoundsCheck(::VirtualFree(p, 0, MEM_RELEASE) != 0, "reservation cleanup");
}
void BoundsSeparateReservations()
{
    // Reserve two independent adjacent 64 KiB allocations; never substitute a false AllocationBase.
    std::uint8_t* p = nullptr;
    std::uint8_t* q = nullptr;
    for (unsigned i=0; i<64 && q == nullptr; ++i) {
        auto address = std::uintptr_t(0xC1000000u) + i * 131072u;
        p = static_cast<std::uint8_t*>(::VirtualAlloc(reinterpret_cast<void*>(address),65536,
                                                    MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE));
        if (!p) continue;
        q = static_cast<std::uint8_t*>(::VirtualAlloc(p + 65536,65536,
                                                    MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE));
        if (!q) { BoundsCheck(::VirtualFree(p,0,MEM_RELEASE)!=0,"probe cleanup"); p=nullptr; }
    }
    if (!q) BoundsFail("adjacent independent reservations unavailable",77);
    ::EnterCriticalSection(&gAllocatorSentinel);
    auto* left = BoundsRecord(p + 61440,1,p);
    auto* right = BoundsRecord(q,1,q);
    (void)ReleaseHeapRecord(right);
    (void)ReleaseHeapRecord(left);
    BoundsCheck(left->sizePages==1 && right->sizePages==1, "different reservations must not merge");
    BoundsCheck(GetPageOwner(p+61440)==left && GetPageOwner(q)==right,"separate ownership");
    BoundsDispose(left); BoundsDispose(right);
    ::LeaveCriticalSection(&gAllocatorSentinel);
    BoundsCheck(::VirtualFree(p,0,MEM_RELEASE)!=0 && ::VirtualFree(q,0,MEM_RELEASE)!=0,"separate cleanup");
}
} // namespace
extern "C" int FafRunAllocatorBoundsCase(const char* mode)
{
    BOOL wow64 = FALSE;
    BoundsCheck(::IsWow64Process(::GetCurrentProcess(), &wow64) && wow64, "requires x86 on 64-bit Windows");
    // Initialization goes through public allocator, never overwrites initialized globals.
    BoundsSmoke();
    BoundsCheck(gAllocatorSentinelIsCritical && gPageOwnerByPage != nullptr, "production initialization");
    if (std::strcmp(mode,"normal") == 0) {
        HANDLE threads[2] = {::CreateThread(nullptr,0,BoundsThread,nullptr,0,nullptr),
                             ::CreateThread(nullptr,0,BoundsThread,nullptr,0,nullptr)};
        BoundsCheck(threads[0] && threads[1],"thread creation");
        BoundsCheck(::WaitForMultipleObjects(2,threads,TRUE,60000)==WAIT_OBJECT_0,"thread completion");
        for (auto handle: threads) { DWORD code=1; BoundsCheck(::GetExitCodeThread(handle,&code)&&code==0,"thread exit"); ::CloseHandle(handle); }
    } else if (std::strcmp(mode,"low") == 0) {
        BoundsMerge(0x20000000u,false); BoundsMerge(0x20000000u,true);
    } else if (std::strcmp(mode,"high") == 0) {
        BoundsMerge(0xC0000000u,false); BoundsMerge(0xC0000000u,true);
    } else if (std::strcmp(mode,"map") == 0) {
        // Baseline refuses BEFORE its known out-of-bounds access; no deliberate corruption.
        BoundsCheck(kPageOwnerMapBytes/sizeof(HeapRecord*) == 0x100000u,"full x86 map capacity");
        BoundsCheck(kMaxPageIndex == 0x100000u,"exclusive bound");
        BoundsMerge(0xFFC00000u,false); BoundsMerge(0xFFC00000u,true);
    } else if (std::strcmp(mode,"separate") == 0) {
        BoundsSeparateReservations();
    } else BoundsFail("unknown test case");
    std::printf("PASS native production-backed allocator case=%s\n",mode);
    return 0;
}
