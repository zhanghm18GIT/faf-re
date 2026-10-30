// Controlled component inputs, NOT an observed live match/scheduler/replay.
// Real Entity serialization ctor, real CTextureScroller::Tick, real packet fill.
#include <bit>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "moho/entity/Entity.h"
#include "moho/entity/CTextureScroller.h"
#include "moho/entity/TreadComponentTestSeams.h"
#include "moho/mesh/Mesh.h"
#include "gpg/gal/MeshVertex.h"
#include "gpg/gal/MeshFormatter.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SimWorkerPool.h"
#include "moho/sim/UnitUpdateFill.h"
namespace {
using namespace moho;
void Check(bool ok,const char* text) { if(!ok) {std::fprintf(stderr,"FAIL %s\n",text);std::exit(1);} }
bool Near(float a,float b) {return std::fabs(a-b)<0.00001f;}
std::uint32_t Bits(float v) {return std::bit_cast<std::uint32_t>(v);}
struct Fixture {
  Entity entity{nullptr,0u}; // Legal serializer constructor, no fake storage or Sim.
  CTextureScroller scroller{&entity};
  Fixture() {
    SScroller def; def.mType=SCROLLTYPE_MotionDerived;def.mFloat24=1.0f;def.mFloat28=1.0f;
    scroller.SetScroller(def);
  }
  SSTIEntityVariableData& Data() {return entity.mVarDat;}
  void Step(float dz) {
    Data().mLastTransform=Data().mCurTransform;
    Data().mCurTransform.pos_.z+=dz;
    scroller.Tick();
  }
};
void Motion() {
  Fixture f;
  unsigned zero=0;
  for(unsigned tick=0;tick<1024;++tick) {
    f.Step(.125f);
    const auto& d=f.Data();
    zero+=(d.mScrollBeatEnd.x==d.mScrollBeatStart.x && d.mScrollBeatEnd.y==d.mScrollBeatStart.y);
    Check(d.mScrollBeatEnd.x-d.mScrollBeatStart.x==.125f,"straight source delta");
    Check(d.mScrollBeatEnd.x==d.mScrollBeatEnd.y,"straight sides equal");
  }
  Check(zero==0,"no generated straight fixture zero gaps");
  float previousStart=f.Data().mScrollBeatStart.x,previousEnd=f.Data().mScrollBeatEnd.x;
  f.Step(0.0f);
  Check(f.Data().mScrollBeatStart.x==previousStart && f.Data().mScrollBeatEnd.x==previousEnd,"stationary guard retains previous endpoint pair");
  f.Step(-.125f);Check(f.Data().mScrollBeatEnd.x-f.Data().mScrollBeatStart.x==-.125f,"reverse restart");
  Fixture left,right;
  left.Data().mCurTransform.pos_.z=1.0f; right.Data().mCurTransform.pos_.z=1.0f;
  const float sine=std::sin(.1f),cosine=std::cos(.1f);
  left.Data().mCurTransform.orient_={cosine,0.0f,sine,0.0f};
  right.Data().mCurTransform.orient_={cosine,0.0f,-sine,0.0f};
  left.scroller.Tick();right.scroller.Tick();
  Check(Near(left.Data().mScrollBeatEnd.x,right.Data().mScrollBeatEnd.y) && Near(left.Data().mScrollBeatEnd.y,right.Data().mScrollBeatEnd.x),"yaw sign swaps differential deltas");
  Check(left.Data().mScrollBeatEnd.x<left.Data().mScrollBeatEnd.y,"positive yaw +X inside");
  Fixture rotation;
  rotation.Data().mCurTransform.orient_={cosine,0.0f,sine,0.0f};
  rotation.scroller.Tick();
  Check(rotation.Data().mScrollBeatEnd.x==0.0f && rotation.Data().mScrollBeatEnd.y==0.0f,"current pure-rotation early return observation");
  std::printf("FINDING fixture_only pure_rotation output=(0,0) rigid_side_expected=(%.9g,%.9g); stationary_keeps_prior_pair=true; straight_ticks=1024 zero_gaps=%u\n",-std::sin(.2f),std::sin(.2f),zero);
}
void Consume(const SSTIEntityVariableData& source,float alpha,float& x,float& y) {
  // Real empty spatial database outlives the mesh; null resource uses default skeleton.
  SpatialDB<MeshInstance> spatialDb;
  MeshInstance mesh({1.0f,1.0f,1.0f},&spatialDb,0,0,false,{});
  TreadTestPublishMesh(&mesh,source);
  Check(Bits(mesh.scroll1.x)==Bits(source.mScrollBeatStart.x) && Bits(mesh.scroll1.y)==Bits(source.mScrollBeatStart.y) && Bits(mesh.scroll2.x)==Bits(source.mScrollBeatEnd.x) && Bits(mesh.scroll2.y)==Bits(source.mScrollBeatEnd.y),"actual UserEntity copy lane bits");
  gpg::gal::MeshVertex staging{};
  MeshInstance::sCurrentInterpolant=alpha;
  TreadTestInterpolateMesh(&mesh,staging);
  x=staging.scroll[0];y=staging.scroll[1];
}
void Phase() {
  Check(gpg::gal::sMeshAllowFloat16==0 && gpg::gal::sMeshAllowInstancing==1,"current merged #222 defaults");
  Fixture consumer;
  for(unsigned tick=0;tick<(1u<<19);++tick) consumer.Step(.125f);
  Check(consumer.Data().mScrollBeatEnd.x==65536.0f,"cumulative producer phase 65536 no seeded endpoints");
  consumer.scroller.mScroller.mFloat28=.125f;consumer.Step(.125f);
  Check(consumer.Data().mScrollBeatEnd.x-consumer.Data().mScrollBeatStart.x==.015625f,"source small delta survives");
  float x=0,y=0;Consume(consumer.Data(),.25f,x,y);
  Check(x==consumer.Data().mScrollBeatStart.x && y==consumer.Data().mScrollBeatStart.y,"actual consumer float32 quarter sample collapsed");
  std::printf("FINDING fixture_only consumer_precision ticks=%u phase=%.9g delta=%.9g alpha=.25 output=%.9g fullfloat_default=1\n",(1u<<19)+1,consumer.Data().mScrollBeatStart.x,consumer.Data().mScrollBeatEnd.x-consumer.Data().mScrollBeatStart.x,x);
  Fixture producer;
  for(unsigned tick=0;tick<(1u<<21);++tick) producer.Step(.125f);
  Check(producer.Data().mScrollBeatEnd.x==262144.0f,"cumulative producer phase 262144 no seeded endpoints");
  producer.scroller.mScroller.mFloat28=.08f;
  for(unsigned i=0;i<6;++i) {
    producer.Step(.125f);
    Check(producer.Data().mCurTransform.pos_.z>producer.Data().mLastTransform.pos_.z,"real nonzero fixture translation");
    Check(producer.Data().mScrollBeatEnd.x==producer.Data().mScrollBeatStart.x && producer.Data().mScrollBeatEnd.y==producer.Data().mScrollBeatStart.y,"source float32 accumulation plateau");
  }
  std::puts("FINDING fixture_only source_precision naturally_accumulated_phase=262144 nonzero_translation=.125 scale=.08 zero_updates=6; not_historical_game_gap_reproduction");
}
void SnapshotRun(int workers,bool deferred,bool finish) {
  sim_Workers=workers;sim_ParallelSync=true;sim_ParallelEntitySync=deferred;
  Fixture fixture;
  constexpr unsigned count=1024;
  std::vector<SSTIEntityVariableData> generated(count);
  for(unsigned i=0;i<count;++i) {
    fixture.Data().mLastTransform=fixture.Data().mCurTransform;
    fixture.Data().mCurTransform.pos_.z+=.0625f;
    const float yaw=(i%2==0)?.05f:-.05f;
    fixture.Data().mCurTransform.orient_={std::cos(yaw),0.0f,std::sin(yaw),0.0f};
    fixture.scroller.Tick();generated[i]=fixture.Data();
  }
  Check(generated[0].mScrollBeatEnd.x!=generated[0].mScrollBeatEnd.y,"asymmetric generated lanes detect swaps");
  SSyncData packet;unsigned queuedDeferred=0;
  {
    CUnitUpdateFills fills(&packet);
    for(unsigned i=0;i<count;++i) {
      auto* entry=QueueEntityVariableUpdateDeferred(&packet,static_cast<EntId>(i+1),generated[i]);
      if(entry) ++queuedDeferred;
      else entry=QueueEntityVariableUpdate(&packet,static_cast<EntId>(i+1),generated[i]);
      Check(entry!=nullptr,"current upstream entity queue");
    }
    packet.mEntityUpdates.reserve(packet.mEntityUpdates.capacity()+1024);
    if(finish) fills.Finish();
  }
  Check(queuedDeferred==((workers>0 && deferred)?count:0u),"observed intended serial/deferred path");
  for(unsigned i=0;i<count;++i) {
    const auto& d=packet.mEntityUpdates[i].mVariableData;const auto& s=generated[i];
    Check(Bits(d.mScrollBeatStart.x)==Bits(s.mScrollBeatStart.x) && Bits(d.mScrollBeatStart.y)==Bits(s.mScrollBeatStart.y) && Bits(d.mScrollBeatEnd.x)==Bits(s.mScrollBeatEnd.x) && Bits(d.mScrollBeatEnd.y)==Bits(s.mScrollBeatEnd.y),"actual source to packet four-lane equality");
    if(i==0 || i==count-1) {float x,y;Consume(d,.5f,x,y);Check(x==s.mScrollBeatStart.x+(s.mScrollBeatEnd.x-s.mScrollBeatStart.x)*.5f && y==s.mScrollBeatStart.y+(s.mScrollBeatEnd.y-s.mScrollBeatStart.y)*.5f,"source packet publish consumer continuity");}
  }
  if(workers>0 && deferred && finish) Check(CSimWorkerPool::Get().WorkerCount()>0,"worker pool configured nonzero");
  std::printf("fixture_packet workers=%d deferred=%u finish=%d records=%u four_lane_mismatches=0\n",workers,queuedDeferred,finish,count);
}
}
int main(int argc,char** argv) {
  Check(argc==2,"one fixture selector");
  if(std::strcmp(argv[1],"motion")==0) Motion();
  else if(std::strcmp(argv[1],"phase")==0) Phase();
  else if(std::strcmp(argv[1],"snapshot")==0) {SnapshotRun(0,true,true);SnapshotRun(2,false,true);SnapshotRun(2,true,true);SnapshotRun(2,true,false);}
  else Check(false,"unknown fixture");
  std::printf("PASS tread_%s_fixture; controlled production-backed component evidence, not live Sim/GPU/replay\n",argv[1]);return 0;
}
