// Original project fixture. SPDX-License-Identifier: MIT
// Full-screen triangle: (-1,-1), (3,-1), (-1,3). No vertex buffer.
float4 main(uint vertex_id : SV_VertexID) : SV_Position
{
    float x = vertex_id == 1 ? 3.0 : -1.0;
    float y = vertex_id == 2 ? 3.0 : -1.0;
    return float4(x, y, 0.0, 1.0);
}
