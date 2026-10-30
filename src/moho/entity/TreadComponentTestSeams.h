#pragma once
#if !defined(FAF_TREAD_TEST_SEAMS)
#error This header belongs only to the isolated tread component test build
#endif
namespace gpg::gal { struct MeshVertex; }
namespace moho {
class MeshInstance;
struct SSTIEntityVariableData;
void TreadTestPublishMesh(MeshInstance*, const SSTIEntityVariableData&);
void TreadTestInterpolateMesh(const MeshInstance*, gpg::gal::MeshVertex&);
}
