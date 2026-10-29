// Original project fixture. SPDX-License-Identifier: MIT
// RGBA8 expected output (0, 255, 0, 255), distinct from magenta clear.
float4 main() : SV_Target0
{
    return float4(0.0, 1.0, 0.0, 1.0);
}
