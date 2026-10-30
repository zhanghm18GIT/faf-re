// Public allocator regression linked against the unchanged faf_engine objects.
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <array>
#include <thread>
#include <atomic>
#if !defined(_WIN32) || !(defined(_M_X64) || defined(__x86_64__))
#error This acceptance test requires native Windows x64
#endif
// Match the exported definitions in src/gpg/core/utils/Global.cpp.
extern "C" void* __cdecl malloc_0(std::uint32_t size);
extern "C" void __cdecl free_0(void* ptr);
extern "C" std::size_t __cdecl msize(void* ptr);
extern "C" void* __cdecl realloc_0(void* ptr, std::size_t size);
namespace {
std::atomic<unsigned> high{0}, allocations{0};
void Check(bool ok, const char* message) {
    if (!ok) { std::fprintf(stderr,"FAIL: %s\n",message); std::exit(1); }
}
void Record(void* p) {
    Check(p != nullptr,"allocation succeeded"); ++allocations;
    if (reinterpret_cast<std::uintptr_t>(p) >= 0x100000000ull) ++high;
    Check((reinterpret_cast<std::uintptr_t>(p) & 15u) == 0,"x64 16-byte alignment");
}
unsigned char Pattern(std::size_t i) { return static_cast<unsigned char>((i*37u+113u)&255u); }
void Verify(const void* p,std::size_t n) {
    for(std::size_t i=0;i<n;++i) Check(static_cast<const unsigned char*>(p)[i]==Pattern(i),"payload preserved");
}
void Exercise(std::uint32_t n) {
    auto* p=static_cast<unsigned char*>(malloc_0(n)); Record(p);
    Check(msize(p)>=n,"initial size");
    for(std::size_t i=0;i<n;++i)p[i]=Pattern(i);
    const std::size_t grown=2u*n+8193u; // crosses the pool/system boundary for small sizes
    auto* q=static_cast<unsigned char*>(realloc_0(p,grown));Record(q);
    Check(msize(q)>=grown,"grown size");Verify(q,n);
    for(std::size_t i=0;i<grown;++i)q[i]=Pattern(i);
    auto* r=static_cast<unsigned char*>(realloc_0(q,17));Record(r);
    Check(msize(r)>=17,"shrunk size");Verify(r,17);free_0(r);
}
}
int main(int argc,char** argv) {
    static_assert(sizeof(void*)==8);
    Check(argc==2 && (std::strcmp(argv[1],"pool-on")==0 || std::strcmp(argv[1],"pool-off")==0),"mode required");
    const char* expected=std::strcmp(argv[1],"pool-on")==0 ? "1":"0";
    const char* actual=std::getenv("FAF_SMALLPOOL");
    Check(actual!=nullptr && std::strcmp(actual,expected)==0,"launch-time pool environment");
    // Do not reserve low VA, alter globals or request FAF_HIGHMEM; actual addresses are observed.
    free_0(nullptr);Check(msize(nullptr)==0,"null size");
    auto* p=realloc_0(nullptr,47);Record(p);Check(msize(p)>=47,"null realloc allocation");
    Check(realloc_0(p,0)==nullptr,"zero realloc frees");
    constexpr std::array<std::uint32_t,20> sizes={0,1,15,16,17,255,256,257,511,512,513,1023,1024,2048,4095,4096,4097,16384,65536,65537};
    for(auto n:sizes)Exercise(n);
    std::array<void*,128> blocks{};
    for(std::size_t i=0;i<blocks.size();++i){
        auto n=static_cast<std::uint32_t>(i%2 ? 4096:4097);
        blocks[i]=malloc_0(n);Record(blocks[i]);Check(msize(blocks[i])>=n,"batch size");
        std::memset(blocks[i],static_cast<int>(i),n);
    }
    // Free allocations on another real thread; then allocate again after TLS cleanup.
    std::thread consumer([&]{for(std::size_t i=0;i<blocks.size();++i){
        auto n=i%2 ? 4096u:4097u;
        for(unsigned j=0;j<n;++j)Check(static_cast<unsigned char*>(blocks[i])[j]==static_cast<unsigned char>(i),"cross-thread payload");
        free_0(blocks[i]);blocks[i]=nullptr;
    }});consumer.join();
    std::thread producer([]{for(unsigned i=0;i<32;++i)Exercise(i%2?4096:4097);});producer.join();
    for(auto n:sizes)Exercise(n);
    std::printf("mode=%s allocations=%u above4GiB=%u\n",argv[1],allocations.load(),high.load());
    // A low-address-only run does not establish this task's high-address runtime evidence.
    Check(high.load()>0,"at least one actual allocation above 4GiB");
    std::printf("PASS x64 public allocator mode=%s\n",argv[1]);
}
